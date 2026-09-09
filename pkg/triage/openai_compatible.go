package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

// OpenAICompatibleProvider speaks the widely adopted chat-completions
// protocol used by OpenAI, Ollama, LocalAI, LiteLLM, Groq, DeepSeek, and
// compatible self-hosted gateways. The profile validation remains the trust
// boundary for endpoints and credentials.
type OpenAICompatibleProvider struct {
	profile      ProviderProfile
	client       *http.Client
	endpoint     string
	secretValues []string
	redactor     *sanitizer.Redactor
}

type compatibleMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type compatibleChatRequest struct {
	Model          string              `json:"model"`
	Messages       []compatibleMessage `json:"messages"`
	MaxTokens      int                 `json:"max_tokens"`
	Temperature    *float64            `json:"temperature,omitempty"`
	TopP           *float64            `json:"top_p,omitempty"`
	Stop           []string            `json:"stop,omitempty"`
	ResponseFormat *responseFormat     `json:"response_format,omitempty"`
}

type compatibleChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage compatibleUsage `json:"usage"`
}

type compatibleUsage struct {
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

func (usage compatibleUsage) providerTokenUsage() ProviderTokenUsage {
	input := usage.InputTokens
	if input == 0 {
		input = usage.PromptTokens
	}
	output := usage.OutputTokens
	if output == 0 {
		output = usage.CompletionTokens
	}
	return boundProviderTokenUsage(ProviderTokenUsage{
		InputTokens:  input,
		OutputTokens: output,
		TotalTokens:  usage.TotalTokens,
	})
}

type compatibleResponsesRequest struct {
	Model           string               `json:"model"`
	Instructions    string               `json:"instructions,omitempty"`
	Input           string               `json:"input"`
	MaxOutputTokens int                  `json:"max_output_tokens"`
	Temperature     *float64             `json:"temperature,omitempty"`
	TopP            *float64             `json:"top_p,omitempty"`
	Stop            []string             `json:"stop,omitempty"`
	Text            *responsesTextConfig `json:"text,omitempty"`
}

type responsesTextConfig struct {
	Format *responseFormat `json:"format,omitempty"`
}

// NewOpenAICompatibleProvider validates and constructs a provider without
// contacting the configured endpoint.
func NewOpenAICompatibleProvider(profile ProviderProfile) (*OpenAICompatibleProvider, error) {
	normalized, err := profile.Normalize()
	if err != nil {
		return nil, err
	}
	if !openAICompatibleProviderSupportsWire(normalized.Provider, normalized.WireAPI) {
		return nil, providerError(ProviderErrorValidation, normalized.Provider, "construction", ErrProviderValidation)
	}

	secrets := append([]string(nil), normalized.SecretValues...)
	if normalized.APIKey != "" {
		secrets = append(secrets, normalized.APIKey)
	}
	if normalized.Token != "" {
		secrets = append(secrets, normalized.Token)
	}
	for _, value := range normalized.Headers {
		secrets = append(secrets, value)
	}
	for _, values := range normalized.CustomHeaders {
		secrets = append(secrets, values...)
	}
	redactor := sanitizer.NewRedactor(secrets...)

	client := &http.Client{Timeout: normalized.Timeout}
	if normalized.HTTPClient != nil {
		copy := *normalized.HTTPClient
		client = &copy
		if client.Timeout == 0 {
			client.Timeout = normalized.Timeout
		}
	}
	baseTransport := client.Transport
	if normalized.Transport != nil {
		baseTransport = normalized.Transport
	}
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	if transport, ok := baseTransport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.DialContext = safeProviderDialContext
		if normalized.ProxyURL != "" {
			proxy, parseErr := url.Parse(normalized.ProxyURL)
			if parseErr != nil {
				return nil, providerError(ProviderErrorEndpoint, normalized.Provider, "proxy", ErrEndpointNotAllowed)
			}
			clone.Proxy = http.ProxyURL(proxy)
		}
		client.Transport = newCancellationTransport(clone)
	} else {
		client.Transport = baseTransport
	}

	return &OpenAICompatibleProvider{
		profile:      normalized,
		client:       client,
		endpoint:     strings.TrimRight(normalized.Endpoint, "/"),
		secretValues: secrets,
		redactor:     redactor,
	}, nil
}

func (p *OpenAICompatibleProvider) Name() string {
	if p == nil {
		return "OpenAI-compatible"
	}
	return p.redactor.SanitizeText("OpenAI-compatible (" + p.profile.Provider + "/" + p.profile.Model + ")")
}

func (p *OpenAICompatibleProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if p == nil || issue == nil {
		err := providerError(ProviderErrorValidation, p.Name(), "diagnose", ErrProviderValidation)
		observeProviderError(ctx, "provider", "diagnose", err)
		return nil, err
	}
	prompt := BuildPromptWithSecrets(issue, p.secretValues...)
	var raw string
	var err error
	if p.profile.WireAPI == WireAPIResponses {
		raw, err = p.sendResponses(ctx, SystemPrompt, prompt, true, "diagnose")
	} else {
		raw, err = p.send(ctx, p.newRequest(SystemPrompt, prompt, true), "diagnose")
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

func (p *OpenAICompatibleProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	if p == nil {
		err := providerError(ProviderErrorValidation, "provider", "explain", ErrProviderValidation)
		observeProviderError(ctx, "provider", "explain", err)
		return "", err
	}
	query = p.redactor.SanitizeText(query)
	content := query
	if issue != nil {
		content = fmt.Sprintf("Cluster Anomaly Context:\n%s\n\nUser Question:\n%s", BuildPromptWithSecrets(issue, p.secretValues...), query)
	}
	var raw string
	var err error
	if p.profile.WireAPI == WireAPIResponses {
		raw, err = p.sendResponses(ctx, ChatSystemPrompt, content, false, "explain")
	} else {
		raw, err = p.send(ctx, p.newRequest(ChatSystemPrompt, content, false), "explain")
	}
	if err != nil {
		observeProviderError(ctx, p.Name(), "explain", err)
		return "", err
	}
	return p.redactor.SanitizeText(raw), nil
}

func (p *OpenAICompatibleProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	if p == nil {
		ctx = normalizeContext(ctx)
		operation := safeStructuredTaskOperationLabel(task.Operation)
		err := providerError(ProviderErrorValidation, "OpenAI-compatible", operation, ErrProviderValidation)
		observeProviderError(ctx, "OpenAI-compatible", operation, err)
		return StructuredTaskResult{}, err
	}
	provider := p.Name()
	ctx, prepared, err := prepareStructuredTask(ctx, provider, task, p.redactor, p.profile.MaxRequestBytes, p.profile.MaxResponseBytes)
	if err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	if !openAICompatibleProviderSupportsWire(p.profile.Provider, p.profile.WireAPI) {
		err := structuredTaskUnsupported(provider, StructuredTask{Operation: prepared.Operation})
		observeProviderError(ctx, provider, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}

	var result StructuredTaskResult
	if p.profile.WireAPI == WireAPIResponses {
		result, err = p.sendResponsesResult(ctx, prepared.SystemPrompt, prepared.UserPrompt, true, prepared.Operation, prepared.MaxOutputBytes)
	} else {
		result, err = p.sendResult(ctx, p.newRequest(prepared.SystemPrompt, prepared.UserPrompt, true), prepared.Operation, prepared.MaxOutputBytes)
	}
	if err != nil {
		observeProviderError(ctx, provider, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}
	result, err = finalizeStructuredTaskResult(provider, prepared, result, p.redactor)
	if err != nil {
		observeProviderError(ctx, provider, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}
	return result, nil
}

// openAICompatibleProviderSupportsWire is the adapter's complete wire matrix.
// OpenAI (including the normalized codex alias) supports both native APIs;
// compatible gateways and third-party providers use chat completions only.
func openAICompatibleProviderSupportsWire(provider string, wireAPI WireAPI) bool {
	switch provider {
	case "openai":
		return wireAPI == WireAPIChat || wireAPI == WireAPIResponses
	case "localai", "ollama", "litellm", "groq", "deepseek", "custom":
		return wireAPI == WireAPIChat
	default:
		return false
	}
}

func (p *OpenAICompatibleProvider) newResponsesRequest(system, user string, structured bool) compatibleResponsesRequest {
	request := compatibleResponsesRequest{
		Model:           p.profile.Model,
		Instructions:    p.redactor.SanitizeText(system),
		Input:           p.redactor.SanitizeText(user),
		MaxOutputTokens: p.profile.MaxTokens,
		Stop:            append([]string(nil), p.profile.Stop...),
	}
	if p.profile.TemperatureSet || p.profile.Temperature != 0 {
		value := p.profile.Temperature
		request.Temperature = &value
	}
	if p.profile.TopPSet || p.profile.TopP != 0 {
		value := p.profile.TopP
		request.TopP = &value
	}
	if structured {
		request.Text = &responsesTextConfig{Format: &responseFormat{Type: "json_object"}}
	}
	return request
}

func (p *OpenAICompatibleProvider) newRequest(system, user string, structured bool) compatibleChatRequest {
	request := compatibleChatRequest{
		Model: p.profile.Model,
		Messages: []compatibleMessage{
			{Role: "system", Content: p.redactor.SanitizeText(system)},
			{Role: "user", Content: p.redactor.SanitizeText(user)},
		},
		MaxTokens: p.profile.MaxTokens,
		Stop:      append([]string(nil), p.profile.Stop...),
	}
	if p.profile.TemperatureSet || p.profile.Temperature != 0 {
		value := p.profile.Temperature
		request.Temperature = &value
	}
	if p.profile.TopPSet || p.profile.TopP != 0 {
		value := p.profile.TopP
		request.TopP = &value
	}
	if structured {
		request.ResponseFormat = &responseFormat{Type: "json_object"}
	}
	return request
}

func (p *OpenAICompatibleProvider) send(ctx context.Context, payload compatibleChatRequest, operation string) (string, error) {
	result, err := p.sendResult(ctx, payload, operation)
	return result.Text, err
}

func (p *OpenAICompatibleProvider) sendResult(ctx context.Context, payload compatibleChatRequest, operation string, maxResponseBytes ...int) (StructuredTaskResult, error) {
	if p == nil || p.client == nil {
		return StructuredTaskResult{}, providerError(ProviderErrorValidation, "provider", operation, ErrProviderValidation)
	}
	ctx = normalizeContext(ctx)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	if len(encoded) > p.profile.MaxRequestBytes {
		return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/chat/completions", bytes.NewReader(encoded))
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorEndpoint, p.Name(), operation, ErrEndpointNotAllowed)
	}
	// A provider may stream or hold a response while the caller cancels. Do
	// not leave that upstream connection reusable after the bounded request.
	request.Close = true
	request.Header.Set("Content-Type", "application/json")
	p.applyHeaders(request)

	response, err := p.client.Do(request)
	if err != nil {
		return StructuredTaskResult{}, classifyCompatibleTransportError(err, p.Name(), operation, ctx)
	}
	defer response.Body.Close()
	body, err := readBoundedProviderResponse(response.Body, structuredTaskReadLimit(p.profile.MaxResponseBytes, maxResponseBytes...))
	if err != nil {
		if errors.Is(err, ErrProviderResponseTooLarge) {
			return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
		}
		return StructuredTaskResult{}, providerError(ProviderErrorTransport, p.Name(), operation, ErrProviderUnavailable)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return StructuredTaskResult{}, providerHTTPError(p.Name(), operation, response.StatusCode)
	}

	var decoded compatibleChatResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	if len(decoded.Choices) == 0 || strings.TrimSpace(decoded.Choices[0].Message.Content) == "" {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	usage := decoded.Usage.providerTokenUsage()
	observeProviderUsage(ctx, p.Name(), operation, usage)
	return StructuredTaskResult{Text: p.redactor.SanitizeText(decoded.Choices[0].Message.Content), Usage: usage}, nil
}

func (p *OpenAICompatibleProvider) sendResponses(ctx context.Context, system, user string, structured bool, operation string) (string, error) {
	result, err := p.sendResponsesResult(ctx, system, user, structured, operation)
	return result.Text, err
}

func (p *OpenAICompatibleProvider) sendResponsesResult(ctx context.Context, system, user string, structured bool, operation string, maxResponseBytes ...int) (StructuredTaskResult, error) {
	if p == nil || p.client == nil {
		return StructuredTaskResult{}, providerError(ProviderErrorValidation, "provider", operation, ErrProviderValidation)
	}
	ctx = normalizeContext(ctx)
	payload := p.newResponsesRequest(system, user, structured)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	if len(encoded) > p.profile.MaxRequestBytes {
		return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/responses", bytes.NewReader(encoded))
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorEndpoint, p.Name(), operation, ErrEndpointNotAllowed)
	}
	request.Close = true
	request.Header.Set("Content-Type", "application/json")
	p.applyHeaders(request)

	response, err := p.client.Do(request)
	if err != nil {
		return StructuredTaskResult{}, classifyCompatibleTransportError(err, p.Name(), operation, ctx)
	}
	defer response.Body.Close()
	body, err := readBoundedProviderResponse(response.Body, structuredTaskReadLimit(p.profile.MaxResponseBytes, maxResponseBytes...))
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
	return StructuredTaskResult{Text: p.redactor.SanitizeText(text), Usage: usage}, nil
}

func extractResponsesUsage(body []byte) ProviderTokenUsage {
	var err error
	body, err = responsesEnvelope(body)
	if err != nil {
		return ProviderTokenUsage{}
	}
	var response struct {
		Usage compatibleUsage `json:"usage"`
	}
	if json.Unmarshal(body, &response) != nil {
		return ProviderTokenUsage{}
	}
	return response.Usage.providerTokenUsage()
}

func extractResponsesText(body []byte) (string, error) {
	var err error
	body, err = responsesEnvelope(body)
	if err != nil {
		return "", err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return "", ErrProviderResponse
	}
	var response struct {
		Status     string            `json:"status"`
		OutputText string            `json:"output_text"`
		Output     []json.RawMessage `json:"output"`
		Error      json.RawMessage   `json:"error"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", ErrProviderResponse
	}
	if response.Status != "completed" {
		return "", ErrProviderResponse
	}
	if len(response.Error) > 0 && string(response.Error) != "null" {
		return "", ErrProviderResponse
	}
	if text := strings.TrimSpace(response.OutputText); text != "" {
		return text, nil
	}
	for _, rawItem := range response.Output {
		var item struct {
			Type       string            `json:"type"`
			Text       string            `json:"text"`
			OutputText string            `json:"output_text"`
			Content    []json.RawMessage `json:"content"`
		}
		if json.Unmarshal(rawItem, &item) != nil {
			return "", ErrProviderResponse
		}
		if item.Type != "" && item.Type != "message" {
			continue
		}
		if text := strings.TrimSpace(item.Text); text != "" {
			return text, nil
		}
		if text := strings.TrimSpace(item.OutputText); text != "" {
			return text, nil
		}
		for _, rawContent := range item.Content {
			var content struct {
				Type       string `json:"type"`
				Text       string `json:"text"`
				OutputText string `json:"output_text"`
			}
			if json.Unmarshal(rawContent, &content) != nil {
				var plain string
				if json.Unmarshal(rawContent, &plain) == nil && strings.TrimSpace(plain) != "" {
					return strings.TrimSpace(plain), nil
				}
				return "", ErrProviderResponse
			}
			if content.Type != "" && content.Type != "output_text" && content.Type != "text" {
				continue
			}
			if text := strings.TrimSpace(content.Text); text != "" {
				return text, nil
			}
			if text := strings.TrimSpace(content.OutputText); text != "" {
				return text, nil
			}
		}
	}
	return "", ErrProviderResponse
}

func (p *OpenAICompatibleProvider) applyHeaders(request *http.Request) {
	if p.profile.APIKey != "" && !hasAuthorizationHeader(p.profile) {
		request.Header.Set("Authorization", "Bearer "+p.profile.APIKey)
	}
	if p.profile.Organization != "" {
		request.Header.Set("OpenAI-Organization", p.profile.Organization)
	}
	for key, value := range p.profile.Headers {
		request.Header.Set(key, value)
	}
	for key, values := range p.profile.CustomHeaders {
		request.Header.Del(key)
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
}

func readBoundedProviderResponse(reader io.Reader, limit int) ([]byte, error) {
	if limit <= 0 {
		limit = maxProviderResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, ErrProviderResponseTooLarge
	}
	return body, nil
}

func classifyCompatibleTransportError(err error, provider, operation string, ctx context.Context) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return providerError(ProviderErrorTimeout, provider, operation, context.DeadlineExceeded)
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return providerError(ProviderErrorCanceled, provider, operation, context.Canceled)
	}
	return providerError(ProviderErrorTransport, provider, operation, ErrProviderUnavailable)
}

// cancellationTransport closes an in-flight HTTP/1 request when its context
// ends. The standard request context stops the client wait, but a provider
// that leaves the request body unread can otherwise keep the server handler
// and socket alive. The tracker closes the exact connection reported for the
// request, independently of transport request bookkeeping.
type cancellationTransport struct {
	base *http.Transport
}

func newCancellationTransport(base *http.Transport) *cancellationTransport {
	if base == nil {
		return nil
	}
	return &cancellationTransport{base: base.Clone()}
}

func (transport *cancellationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	stop := make(chan struct{})
	connection := &requestConnection{}
	trace := &httptrace.ClientTrace{GotConn: connection.gotConn}
	cloned := request.Clone(httptrace.WithClientTrace(request.Context(), trace))
	go func() {
		select {
		case <-request.Context().Done():
			connection.cancel()
		case <-stop:
		}
	}()
	response, err := transport.base.RoundTrip(cloned)
	close(stop)
	return response, err
}

func (transport *cancellationTransport) CloseIdleConnections() {
	transport.base.CloseIdleConnections()
}

type requestConnection struct {
	mu       sync.Mutex
	conn     net.Conn
	canceled bool
}

func (connection *requestConnection) gotConn(info httptrace.GotConnInfo) {
	connection.mu.Lock()
	if connection.canceled {
		connection.mu.Unlock()
		_ = info.Conn.Close()
		return
	}
	connection.conn = info.Conn
	connection.mu.Unlock()
}

func (connection *requestConnection) cancel() {
	connection.mu.Lock()
	connection.canceled = true
	conn := connection.conn
	connection.mu.Unlock()
	if conn != nil {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = conn.Close()
	}
}
