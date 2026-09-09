package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

// CloudProvider is a bounded HTTP adapter for provider APIs whose wire format
// is not the OpenAI chat-completions protocol. It intentionally accepts an
// injected HTTP client so cloud SDKs, workload identity, and test transports
// remain outside the core agent.
type CloudProvider struct {
	profile      ProviderProfile
	client       *http.Client
	endpoint     string
	secretValues []string
	redactor     *sanitizer.Redactor
}

// NewCloudProvider constructs one of the explicitly supported cloud provider
// adapters without contacting the endpoint.
func NewCloudProvider(profile ProviderProfile) (*CloudProvider, error) {
	normalized, err := profile.Normalize()
	if err != nil {
		return nil, err
	}
	if !cloudProviderSupportsWire(normalized.Provider, normalized.WireAPI) {
		return nil, providerError(ProviderErrorValidation, normalized.Provider, "construction", ErrProviderValidation)
	}
	if strings.TrimSpace(normalized.Endpoint) == "" {
		return nil, providerError(ProviderErrorEndpoint, normalized.Provider, "construction", ErrEndpointNotAllowed)
	}
	secrets := append([]string(nil), normalized.SecretValues...)
	if normalized.APIKey != "" {
		secrets = append(secrets, normalized.APIKey)
	}
	if normalized.Token != "" {
		secrets = append(secrets, normalized.Token)
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
	return &CloudProvider{
		profile:      normalized,
		client:       client,
		endpoint:     strings.TrimRight(normalized.Endpoint, "/"),
		secretValues: secrets,
		redactor:     redactor,
	}, nil
}

func isCloudProvider(provider string) bool {
	switch provider {
	case "azureopenai", "bedrock", "cohere", "gemini", "huggingface", "ibm", "oci", "sagemaker", "vertex":
		return true
	default:
		return false
	}
}

// cloudProviderSupportsWire is the complete wire matrix for the bounded HTTP
// cloud adapters. Each current implementation has one provider-specific
// request shape and uses chat as its profile wire contract; none implements
// the OpenAI Responses envelope.
func cloudProviderSupportsWire(provider string, wireAPI WireAPI) bool {
	return isCloudProvider(provider) && wireAPI == WireAPIChat
}

func (p *CloudProvider) Name() string {
	if p == nil {
		return "cloud provider"
	}
	return p.redactor.SanitizeText(p.profile.Provider + " (" + p.profile.Model + ")")
}

func (p *CloudProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if p == nil || issue == nil {
		err := providerError(ProviderErrorValidation, p.Name(), "diagnose", ErrProviderValidation)
		observeProviderError(ctx, "cloud", "diagnose", err)
		return nil, err
	}
	raw, err := p.send(ctx, SystemPrompt, BuildPromptWithSecrets(issue, p.secretValues...), true, "diagnose")
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

func (p *CloudProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	if p == nil {
		err := providerError(ProviderErrorValidation, "provider", "explain", ErrProviderValidation)
		observeProviderError(ctx, "cloud", "explain", err)
		return "", err
	}
	query = p.redactor.SanitizeText(query)
	content := query
	if issue != nil {
		content = fmt.Sprintf("Cluster Anomaly Context:\n%s\n\nUser Question:\n%s", BuildPromptWithSecrets(issue, p.secretValues...), query)
	}
	result, err := p.send(ctx, SystemPrompt, content, false, "explain")
	if err != nil {
		observeProviderError(ctx, p.Name(), "explain", err)
		return "", err
	}
	return p.redactor.SanitizeText(result), nil
}

func (p *CloudProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	if p == nil {
		ctx = normalizeContext(ctx)
		operation := safeStructuredTaskOperationLabel(task.Operation)
		err := providerError(ProviderErrorValidation, "cloud provider", operation, ErrProviderValidation)
		observeProviderError(ctx, "cloud provider", operation, err)
		return StructuredTaskResult{}, err
	}
	provider := p.Name()
	ctx, prepared, err := prepareStructuredTask(ctx, provider, task, p.redactor, p.profile.MaxRequestBytes, p.profile.MaxResponseBytes)
	if err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	if !cloudProviderSupportsStructuredOutput(p.profile.Provider, p.profile.WireAPI) {
		err := structuredTaskUnsupported(provider, StructuredTask{Operation: prepared.Operation})
		observeProviderError(ctx, provider, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}
	result, err := p.sendResult(ctx, prepared.SystemPrompt, prepared.UserPrompt, true, prepared.Operation, prepared.MaxOutputBytes)
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

func cloudProviderSupportsStructuredOutput(provider string, wireAPI WireAPI) bool {
	return provider == "azureopenai" && cloudProviderSupportsWire(provider, wireAPI)
}

func (p *CloudProvider) send(ctx context.Context, system, user string, structured bool, operation string) (string, error) {
	result, err := p.sendResult(ctx, system, user, structured, operation)
	return result.Text, err
}

func (p *CloudProvider) sendResult(ctx context.Context, system, user string, structured bool, operation string, maxResponseBytes ...int) (StructuredTaskResult, error) {
	if p == nil || p.client == nil {
		return StructuredTaskResult{}, providerError(ProviderErrorValidation, "provider", operation, ErrProviderValidation)
	}
	ctx = normalizeContext(ctx)
	payload, path := p.requestPayload(system, user, structured)
	encoded, err := json.Marshal(payload)
	if err != nil {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	if len(encoded) > p.profile.MaxRequestBytes {
		return StructuredTaskResult{}, providerError(ProviderErrorLimit, p.Name(), operation, ErrProviderResponseTooLarge)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+path, bytes.NewReader(encoded))
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
	result, err := extractCloudText(body)
	if err != nil || strings.TrimSpace(result) == "" {
		return StructuredTaskResult{}, providerError(ProviderErrorResponse, p.Name(), operation, ErrProviderResponse)
	}
	usage := extractCloudUsage(body)
	observeProviderUsage(ctx, p.Name(), operation, usage)
	return StructuredTaskResult{Text: p.redactor.SanitizeText(result), Usage: usage}, nil
}

func extractCloudUsage(body []byte) ProviderTokenUsage {
	var value interface{}
	if json.Unmarshal(body, &value) != nil {
		return ProviderTokenUsage{}
	}
	return findCloudUsage(value)
}

func findCloudUsage(value interface{}) ProviderTokenUsage {
	switch typed := value.(type) {
	case []interface{}:
		for _, item := range typed {
			if usage := findCloudUsage(item); usage != (ProviderTokenUsage{}) {
				return usage
			}
		}
	case map[string]interface{}:
		if usageValue, ok := typed["usage"]; ok {
			if usage, ok := usageValue.(map[string]interface{}); ok {
				return boundProviderTokenUsage(ProviderTokenUsage{
					InputTokens:  jsonNumber(usage["input_tokens"], usage["prompt_tokens"]),
					OutputTokens: jsonNumber(usage["output_tokens"], usage["completion_tokens"]),
					TotalTokens:  jsonNumber(usage["total_tokens"]),
				})
			}
		}
		for _, item := range typed {
			if usage := findCloudUsage(item); usage != (ProviderTokenUsage{}) {
				return usage
			}
		}
	}
	return ProviderTokenUsage{}
}

func jsonNumber(values ...interface{}) int64 {
	for _, value := range values {
		if number, ok := value.(float64); ok && number >= 0 && number <= float64(maxObservedProviderTokens) {
			return int64(number)
		}
	}
	return 0
}

func (p *CloudProvider) requestPayload(system, user string, structured bool) (interface{}, string) {
	system = p.redactor.SanitizeText(system)
	user = p.redactor.SanitizeText(user)
	model := p.profile.Model
	maxTokens := p.profile.MaxTokens
	temperature := p.profile.Temperature
	switch p.profile.Provider {
	case "azureopenai":
		payload := map[string]interface{}{
			"model":      model,
			"messages":   []map[string]string{{"role": "system", "content": system}, {"role": "user", "content": user}},
			"max_tokens": maxTokens,
		}
		if structured {
			payload["response_format"] = map[string]string{"type": "json_object"}
		}
		if p.profile.TemperatureSet || temperature != 0 {
			payload["temperature"] = temperature
		}
		return payload, "/chat/completions"
	case "cohere":
		payload := map[string]interface{}{"model": model, "message": user, "max_tokens": maxTokens}
		if p.profile.TemperatureSet || temperature != 0 {
			payload["temperature"] = temperature
		}
		return payload, "/chat"
	case "gemini", "vertex":
		generationConfig := map[string]interface{}{"maxOutputTokens": maxTokens}
		payload := map[string]interface{}{
			"contents":         []map[string]interface{}{{"role": "user", "parts": []map[string]string{{"text": user}}}},
			"generationConfig": generationConfig,
		}
		if p.profile.TemperatureSet || temperature != 0 {
			generationConfig["temperature"] = temperature
		}
		return payload, "/models/" + url.PathEscape(model) + ":generateContent"
	case "huggingface":
		return map[string]interface{}{"inputs": user, "parameters": map[string]interface{}{"max_new_tokens": maxTokens}}, "/models/" + url.PathEscape(model)
	default:
		return map[string]interface{}{"model": model, "prompt": user, "max_tokens": maxTokens, "temperature": temperature}, "/generate"
	}
}

func (p *CloudProvider) applyHeaders(request *http.Request) {
	if p.profile.APIKey != "" {
		switch p.profile.Provider {
		case "azureopenai":
			request.Header.Set("api-key", p.profile.APIKey)
		case "gemini":
			request.Header.Set("x-goog-api-key", p.profile.APIKey)
		default:
			request.Header.Set("Authorization", "Bearer "+p.profile.APIKey)
		}
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

func extractCloudText(body []byte) (string, error) {
	var value interface{}
	if err := json.Unmarshal(body, &value); err != nil {
		return "", err
	}
	if text, ok := findCloudText(value); ok {
		return text, nil
	}
	return "", ErrProviderResponse
}

func findCloudText(value interface{}) (string, bool) {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) != "" {
			return typed, true
		}
	case []interface{}:
		for _, item := range typed {
			if text, ok := findCloudText(item); ok {
				return text, true
			}
		}
	case map[string]interface{}:
		for _, key := range []string{"output_text", "generated_text", "completion", "response", "text", "content"} {
			if item, ok := typed[key]; ok {
				if text, ok := findCloudText(item); ok {
					return text, true
				}
			}
		}
		for _, key := range []string{"choices", "candidates", "outputs", "generations", "message", "parts"} {
			if item, ok := typed[key]; ok {
				if text, ok := findCloudText(item); ok {
					return text, true
				}
			}
		}
	}
	return "", false
}

func safeProviderDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	for _, candidate := range addresses {
		if candidate.IP == nil || (!candidate.IP.IsLoopback() && (candidate.IP.IsPrivate() || candidate.IP.IsLinkLocalUnicast() || candidate.IP.IsUnspecified() || candidate.IP.IsMulticast())) {
			continue
		}
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if dialErr == nil {
			return connection, nil
		}
	}
	return nil, ErrProviderUnavailable
}
