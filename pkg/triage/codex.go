package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

type CodexProvider struct {
	apiKey       string
	model        string
	baseURL      string
	wireAPI      WireAPI
	client       *http.Client
	secretValues []string
	redactor     *sanitizer.Redactor
}

func NewCodexProvider(apiKey, model, baseURL string, secretValues ...string) *CodexProvider {
	return newCodexProvider(apiKey, model, baseURL, WireAPIResponses, secretValues...)
}

func newCodexProvider(apiKey, model, baseURL string, wireAPI WireAPI, secretValues ...string) *CodexProvider {
	if model == "" {
		model = "gpt-4o"
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	secrets := append([]string{apiKey}, secretValues...)
	return &CodexProvider{
		apiKey:       apiKey,
		model:        model,
		baseURL:      baseURL,
		wireAPI:      wireAPI,
		client:       &http.Client{Timeout: 60 * time.Second},
		secretValues: secrets,
		redactor:     sanitizer.NewRedactor(secrets...),
	}
}

func (p *CodexProvider) Name() string {
	if p == nil {
		return "OpenAI/Codex"
	}
	return p.safeRedactor().SanitizeText("OpenAI/Codex (" + p.model + ")")
}

type openAIRequest struct {
	Model          string          `json:"model"`
	Messages       []openAIMessage `json:"messages"`
	ResponseFormat *responseFormat `json:"response_format,omitempty"`
}

type responseFormat struct {
	Type string `json:"type"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
	Usage compatibleUsage `json:"usage"`
}

func (p *CodexProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if p == nil || issue == nil {
		err := providerError(ProviderErrorValidation, p.Name(), "diagnose", ErrProviderValidation)
		observeProviderError(ctx, "codex", "diagnose", err)
		return nil, err
	}
	prompt := BuildPromptWithSecrets(issue, p.secretValues...)

	reqBody := openAIRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{Role: "system", Content: SystemPrompt},
			{Role: "user", Content: prompt},
		},
		ResponseFormat: &responseFormat{Type: "json_object"},
	}

	var raw string
	var err error
	if p.wireAPI == WireAPIResponses {
		raw, err = p.sendResponses(ctx, SystemPrompt, prompt, true, "diagnose")
	} else {
		raw, err = p.sendRequest(ctx, reqBody, "diagnose")
	}
	if err != nil {
		observeProviderError(ctx, p.Name(), "diagnose", err)
		return nil, err
	}

	diagnosis, err := ParseDiagnosisJSON(raw, issue.ID, p.Name(), p.secretValues...)
	if err != nil {
		observeProviderError(ctx, p.Name(), "diagnose", err)
	}
	return diagnosis, err
}

func (p *CodexProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	if p == nil {
		err := providerError(ProviderErrorValidation, "codex", "explain", ErrProviderValidation)
		observeProviderError(ctx, "codex", "explain", err)
		return "", err
	}
	redactor := p.safeRedactor()
	userContent := redactor.SanitizeText(query)
	if issue != nil {
		userContent = fmt.Sprintf("Cluster Anomaly Context:\n%s\n\nUser Question:\n%s", BuildPromptWithSecrets(issue, p.secretValues...), redactor.SanitizeText(query))
	}

	reqBody := openAIRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{Role: "system", Content: ChatSystemPrompt},
			{Role: "user", Content: userContent},
		},
	}

	var reply string
	var err error
	if p.wireAPI == WireAPIResponses {
		reply, err = p.sendResponses(ctx, ChatSystemPrompt, userContent, false, "explain")
	} else {
		reply, err = p.sendRequest(ctx, reqBody, "explain")
	}
	if err != nil {
		observeProviderError(ctx, p.Name(), "explain", err)
		return "", err
	}
	return redactor.SanitizeText(reply), nil
}

func (p *CodexProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	provider := p.Name()
	ctx, prepared, err := prepareStructuredTask(ctx, provider, task, p.safeRedactor())
	if err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}

	var result StructuredTaskResult
	if p.wireAPI == WireAPIResponses {
		result, err = p.sendResponsesResult(ctx, prepared.SystemPrompt, prepared.UserPrompt, true, prepared.Operation, prepared.MaxOutputBytes)
	} else {
		result, err = p.sendRequestResult(ctx, openAIRequest{
			Model: p.model,
			Messages: []openAIMessage{
				{Role: "system", Content: prepared.SystemPrompt},
				{Role: "user", Content: prepared.UserPrompt},
			},
			ResponseFormat: &responseFormat{Type: "json_object"},
		}, prepared.Operation, prepared.MaxOutputBytes)
	}
	if err != nil {
		observeProviderError(ctx, provider, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}
	result, err = finalizeStructuredTaskResult(provider, prepared, result, p.safeRedactor())
	if err != nil {
		observeProviderError(ctx, provider, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}
	return result, nil
}

func (p *CodexProvider) sendResponses(ctx context.Context, system, user string, structured bool, operation string) (string, error) {
	result, err := p.sendResponsesResult(ctx, system, user, structured, operation)
	return result.Text, err
}

func (p *CodexProvider) sendResponsesResult(ctx context.Context, system, user string, structured bool, operation string, maxResponseBytes ...int) (StructuredTaskResult, error) {
	if p == nil || p.client == nil {
		return StructuredTaskResult{}, providerError(ProviderErrorValidation, "codex", operation, ErrProviderValidation)
	}
	ctx = normalizeContext(ctx)
	payload := compatibleResponsesRequest{
		Model:           p.model,
		Instructions:    p.safeRedactor().SanitizeText(system),
		Input:           p.safeRedactor().SanitizeText(user),
		MaxOutputTokens: defaultMaxTokens,
	}
	if structured {
		payload.Text = &responsesTextConfig{Format: &responseFormat{Type: "json_object"}}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	if len(encoded) > defaultMaxRequestBytes {
		return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.baseURL, "/")+"/responses", bytes.NewReader(encoded))
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorEndpoint, p.Name(), operation, ErrEndpointNotAllowed)
	}
	request.Close = true
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+p.apiKey)

	response, err := p.client.Do(request)
	if err != nil {
		return StructuredTaskResult{}, classifyCompatibleTransportError(err, p.Name(), operation, ctx)
	}
	defer response.Body.Close()
	body, err := readBoundedProviderResponse(response.Body, structuredTaskReadLimit(maxProviderResponseBytes, maxResponseBytes...))
	if err != nil {
		if errors.Is(err, ErrProviderResponseTooLarge) {
			return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
		}
		return StructuredTaskResult{}, providerError(ProviderErrorTransport, p.Name(), operation, ErrProviderUnavailable)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return StructuredTaskResult{}, providerHTTPError(p.Name(), operation, response.StatusCode)
	}
	text, err := extractResponsesText(body)
	if err != nil || strings.TrimSpace(text) == "" {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	usage := extractResponsesUsage(body)
	observeProviderUsage(ctx, p.Name(), operation, usage)
	return StructuredTaskResult{Text: p.safeRedactor().SanitizeText(text), Usage: usage}, nil
}

func (p *CodexProvider) sendRequest(ctx context.Context, reqBody openAIRequest, operations ...string) (string, error) {
	operation := "request"
	if len(operations) > 0 && operations[0] != "" {
		operation = operations[0]
	}
	result, err := p.sendRequestResult(ctx, reqBody, operation)
	return result.Text, err
}

func (p *CodexProvider) sendRequestResult(ctx context.Context, reqBody openAIRequest, operation string, maxResponseBytes ...int) (StructuredTaskResult, error) {
	if p == nil || p.client == nil {
		return StructuredTaskResult{}, providerError(ProviderErrorValidation, "codex", "request", ErrProviderValidation)
	}
	if operation == "" {
		operation = "request"
	}
	ctx = normalizeContext(ctx)
	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	if len(payloadBytes) > defaultMaxRequestBytes {
		return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.baseURL, "/")+"/chat/completions", bytes.NewReader(payloadBytes))
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorEndpoint, p.Name(), operation, ErrEndpointNotAllowed)
	}

	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return StructuredTaskResult{}, classifyCompatibleTransportError(err, p.Name(), operation, ctx)
	}
	defer resp.Body.Close()

	body, err := readBoundedProviderResponse(resp.Body, structuredTaskReadLimit(maxProviderResponseBytes, maxResponseBytes...))
	if err != nil {
		if errors.Is(err, ErrProviderResponseTooLarge) {
			return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
		}
		return StructuredTaskResult{}, providerError(ProviderErrorTransport, p.Name(), operation, ErrProviderUnavailable)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return StructuredTaskResult{}, providerHTTPError(p.Name(), operation, resp.StatusCode)
	}

	var openAIResp openAIResponse
	if err := json.Unmarshal(body, &openAIResp); err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}

	if openAIResp.Error != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}

	if len(openAIResp.Choices) == 0 || strings.TrimSpace(openAIResp.Choices[0].Message.Content) == "" {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}

	usage := openAIResp.Usage.providerTokenUsage()
	observeProviderUsage(ctx, p.Name(), operation, usage)
	return StructuredTaskResult{Text: p.safeRedactor().SanitizeText(openAIResp.Choices[0].Message.Content), Usage: usage}, nil
}

func (p *CodexProvider) safeRedactor() *sanitizer.Redactor {
	if p == nil || p.redactor == nil {
		return sanitizer.DefaultRedactor()
	}
	return p.redactor
}
