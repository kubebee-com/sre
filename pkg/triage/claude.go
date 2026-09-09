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

type ClaudeProvider struct {
	apiKey       string
	model        string
	baseURL      string
	client       *http.Client
	secretValues []string
	redactor     *sanitizer.Redactor
}

func NewClaudeProvider(apiKey, model, baseURL string, secretValues ...string) *ClaudeProvider {
	if model == "" {
		model = "claude-3-7-sonnet-20250219"
	}
	if baseURL == "" {
		baseURL = "https://api.anthropic.com/v1"
	}
	secrets := append([]string{apiKey}, secretValues...)
	return &ClaudeProvider{
		apiKey:       apiKey,
		model:        model,
		baseURL:      baseURL,
		client:       &http.Client{Timeout: 60 * time.Second},
		secretValues: secrets,
		redactor:     sanitizer.NewRedactor(secrets...),
	}
}

func (p *ClaudeProvider) Name() string {
	if p == nil {
		return "Anthropic Claude"
	}
	return p.safeRedactor().SanitizeText("Anthropic Claude (" + p.model + ")")
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
	Usage struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

func (p *ClaudeProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if p == nil || issue == nil {
		err := providerError(ProviderErrorValidation, p.Name(), "diagnose", ErrProviderValidation)
		observeProviderError(ctx, "claude", "diagnose", err)
		return nil, err
	}
	prompt := BuildPromptWithSecrets(issue, p.secretValues...)

	reqBody := anthropicRequest{
		Model:     p.model,
		MaxTokens: 2048,
		System:    SystemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	}

	raw, err := p.sendRequest(ctx, reqBody, "diagnose")
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

func (p *ClaudeProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	if p == nil {
		err := providerError(ProviderErrorValidation, "claude", "explain", ErrProviderValidation)
		observeProviderError(ctx, "claude", "explain", err)
		return "", err
	}
	redactor := p.safeRedactor()
	userContent := redactor.SanitizeText(query)
	if issue != nil {
		userContent = fmt.Sprintf("Cluster Anomaly Context:\n%s\n\nUser Question:\n%s", BuildPromptWithSecrets(issue, p.secretValues...), redactor.SanitizeText(query))
	}

	reqBody := anthropicRequest{
		Model:     p.model,
		MaxTokens: 2048,
		System:    ChatSystemPrompt,
		Messages: []anthropicMessage{
			{Role: "user", Content: userContent},
		},
	}

	reply, err := p.sendRequest(ctx, reqBody, "explain")
	if err != nil {
		observeProviderError(ctx, p.Name(), "explain", err)
		return "", err
	}
	return redactor.SanitizeText(reply), nil
}

func (p *ClaudeProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	provider := p.Name()
	ctx, prepared, err := prepareStructuredTask(ctx, provider, task, p.safeRedactor())
	if err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	err = structuredTaskUnsupported(provider, StructuredTask{Operation: prepared.Operation})
	observeProviderError(ctx, provider, prepared.Operation, err)
	return StructuredTaskResult{}, err
}

func (p *ClaudeProvider) sendRequest(ctx context.Context, reqBody anthropicRequest, operations ...string) (string, error) {
	result, err := p.sendRequestResult(ctx, reqBody, operations...)
	return result.Text, err
}

func (p *ClaudeProvider) sendRequestResult(ctx context.Context, reqBody anthropicRequest, operations ...string) (StructuredTaskResult, error) {
	if p == nil || p.client == nil {
		return StructuredTaskResult{}, providerError(ProviderErrorValidation, "claude", "request", ErrProviderValidation)
	}
	operation := "request"
	if len(operations) > 0 && operations[0] != "" {
		operation = operations[0]
	}
	ctx = normalizeContext(ctx)
	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	if len(payloadBytes) > defaultMaxRequestBytes {
		return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.baseURL, "/")+"/messages", bytes.NewReader(payloadBytes))
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorEndpoint, p.Name(), operation, ErrEndpointNotAllowed)
	}

	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.client.Do(req)
	if err != nil {
		return StructuredTaskResult{}, classifyCompatibleTransportError(err, p.Name(), operation, ctx)
	}
	defer resp.Body.Close()

	body, err := readBoundedProviderResponse(resp.Body, structuredTaskReadLimit(maxProviderResponseBytes))
	if err != nil {
		if errors.Is(err, ErrProviderResponseTooLarge) {
			return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
		}
		return StructuredTaskResult{}, providerError(ProviderErrorTransport, p.Name(), operation, ErrProviderUnavailable)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return StructuredTaskResult{}, providerHTTPError(p.Name(), operation, resp.StatusCode)
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(body, &anthropicResp); err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}

	if anthropicResp.Error != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}

	if len(anthropicResp.Content) == 0 || strings.TrimSpace(anthropicResp.Content[0].Text) == "" {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}

	usage := boundProviderTokenUsage(ProviderTokenUsage{InputTokens: anthropicResp.Usage.InputTokens, OutputTokens: anthropicResp.Usage.OutputTokens})
	observeProviderUsage(ctx, p.Name(), operation, usage)
	return StructuredTaskResult{Text: p.safeRedactor().SanitizeText(anthropicResp.Content[0].Text), Usage: usage}, nil
}

func (p *ClaudeProvider) safeRedactor() *sanitizer.Redactor {
	if p == nil || p.redactor == nil {
		return sanitizer.DefaultRedactor()
	}
	return p.redactor
}
