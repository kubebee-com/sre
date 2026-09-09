package triage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/sagemakerruntime"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

const (
	awsProviderContentType = "application/json"
	awsProviderAccept      = "application/json"
	maxAWSRegionLength     = 64
	maxSageMakerEndpoint   = 63
)

// BedrockRuntimeClient is the subset of the AWS SDK v2 client used by the
// provider. Keeping the generated client behind this interface makes tests
// deterministic without replacing the SDK's credential and signing logic.
type BedrockRuntimeClient interface {
	InvokeModel(context.Context, *bedrockruntime.InvokeModelInput, ...func(*bedrockruntime.Options)) (*bedrockruntime.InvokeModelOutput, error)
}

// SageMakerRuntimeClient is the subset of the AWS SDK v2 client used by the
// provider.
type SageMakerRuntimeClient interface {
	InvokeEndpoint(context.Context, *sagemakerruntime.InvokeEndpointInput, ...func(*sagemakerruntime.Options)) (*sagemakerruntime.InvokeEndpointOutput, error)
}

// AWSProviderOptions controls native AWS provider construction. Injecting a
// generated client is preferred for unit tests. AWSConfig, HTTPClient, and
// Transport are available for deterministic SDK transport tests and private
// endpoint deployments; none of these values are serialized or logged.
type AWSProviderOptions struct {
	// Context bounds credential and SDK configuration loading. A nil value
	// uses a process-local background context for backwards compatibility.
	Context context.Context

	BedrockClient   BedrockRuntimeClient
	SageMakerClient SageMakerRuntimeClient

	AWSConfig  *aws.Config
	HTTPClient aws.HTTPClient
	Transport  http.RoundTripper
	Region     string

	// BaseEndpoint overrides the SDK service endpoint. It is intended for
	// private endpoints and local integration tests.
	BaseEndpoint string

	// TargetModel is sent only to SageMaker multi-model endpoints.
	TargetModel string
}

// BedrockProvider invokes Amazon Bedrock Runtime through the AWS SDK v2.
type BedrockProvider struct {
	profile      ProviderProfile
	client       BedrockRuntimeClient
	secretValues []string
	redactor     *sanitizer.Redactor
}

// SageMakerProvider invokes Amazon SageMaker Runtime through the AWS SDK v2.
type SageMakerProvider struct {
	profile      ProviderProfile
	client       SageMakerRuntimeClient
	targetModel  string
	secretValues []string
	redactor     *sanitizer.Redactor
}

// NewBedrockProvider constructs a native Bedrock Runtime provider. The
// optional options argument is intentionally variadic so existing constructor
// style remains concise while tests can inject a generated client.
func NewBedrockProvider(profile ProviderProfile, options ...AWSProviderOptions) (*BedrockProvider, error) {
	awsOptions, err := oneAWSProviderOptions(options)
	if err != nil {
		return nil, providerError(ProviderErrorValidation, "bedrock", "construction", ErrProviderValidation)
	}
	normalized, err := normalizeNativeAWSProfile(profile, "bedrock")
	if err != nil {
		return nil, err
	}
	client := awsOptions.BedrockClient
	if client == nil {
		config, configErr := loadNativeAWSConfig(normalized, awsOptions)
		if configErr != nil {
			return nil, classifyAWSConstructionError("bedrock", configErr)
		}
		client = bedrockruntime.NewFromConfig(config)
	}
	secrets := awsProviderSecrets(normalized)
	return &BedrockProvider{
		profile:      normalized,
		client:       client,
		secretValues: secrets,
		redactor:     sanitizer.NewRedactor(secrets...),
	}, nil
}

// NewSageMakerProvider constructs a native SageMaker Runtime provider.
func NewSageMakerProvider(profile ProviderProfile, options ...AWSProviderOptions) (*SageMakerProvider, error) {
	awsOptions, err := oneAWSProviderOptions(options)
	if err != nil {
		return nil, providerError(ProviderErrorValidation, "sagemaker", "construction", ErrProviderValidation)
	}
	normalized, err := normalizeNativeAWSProfile(profile, "sagemaker")
	if err != nil {
		return nil, err
	}
	client := awsOptions.SageMakerClient
	if client == nil {
		config, configErr := loadNativeAWSConfig(normalized, awsOptions)
		if configErr != nil {
			return nil, classifyAWSConstructionError("sagemaker", configErr)
		}
		client = sagemakerruntime.NewFromConfig(config)
	}
	secrets := awsProviderSecrets(normalized)
	return &SageMakerProvider{
		profile:      normalized,
		client:       client,
		targetModel:  strings.TrimSpace(awsOptions.TargetModel),
		secretValues: secrets,
		redactor:     sanitizer.NewRedactor(secrets...),
	}, nil
}

func oneAWSProviderOptions(options []AWSProviderOptions) (AWSProviderOptions, error) {
	if len(options) > 1 {
		return AWSProviderOptions{}, ErrProviderValidation
	}
	if len(options) == 1 {
		return options[0], nil
	}
	return AWSProviderOptions{}, nil
}

func normalizeNativeAWSProfile(profile ProviderProfile, provider string) (ProviderProfile, error) {
	configuredProvider := normalizeProviderName(profile.Provider)
	if configuredProvider == "" {
		profile.Provider = provider
	} else if configuredProvider != provider {
		return ProviderProfile{}, providerError(ProviderErrorValidation, provider, "construction", ErrProviderValidation)
	}
	profile.Mode = ProviderModeAWS
	normalized, err := profile.Normalize()
	if err != nil {
		return ProviderProfile{}, err
	}
	if normalized.Provider != provider || strings.ContainsAny(normalized.Model, " \t\r\n") {
		return ProviderProfile{}, providerError(ProviderErrorValidation, provider, "construction", ErrProviderValidation)
	}
	if normalized.AWSRegion != "" && (len(normalized.AWSRegion) > maxAWSRegionLength || strings.ContainsAny(normalized.AWSRegion, " \t\r\n")) {
		return ProviderProfile{}, providerError(ProviderErrorValidation, provider, "construction", ErrProviderValidation)
	}
	if provider == "sagemaker" {
		if !validSageMakerEndpointName(normalized.Endpoint) {
			return ProviderProfile{}, providerError(ProviderErrorValidation, provider, "construction", ErrProviderValidation)
		}
	}
	if provider == "bedrock" && normalized.Endpoint != "" {
		if err := validateEndpointPolicy(normalized.Endpoint, normalized.EndpointAllowlist, false, normalized.AllowLoopback, provider); err != nil {
			return ProviderProfile{}, err
		}
	}
	return normalized, nil
}

func validSageMakerEndpointName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxSageMakerEndpoint || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for _, char := range name {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func awsProviderSecrets(profile ProviderProfile) []string {
	secrets := append([]string(nil), profile.SecretValues...)
	if profile.APIKey != "" {
		secrets = append(secrets, profile.APIKey)
	}
	if profile.Token != "" {
		secrets = append(secrets, profile.Token)
	}
	return secrets
}

func loadNativeAWSConfig(profile ProviderProfile, options AWSProviderOptions) (aws.Config, error) {
	httpClient, err := nativeAWSHTTPClient(profile.Timeout, options)
	if err != nil {
		return aws.Config{}, err
	}
	var config aws.Config
	if options.AWSConfig != nil {
		config = *options.AWSConfig
	} else {
		loadOptions := make([]func(*awsconfig.LoadOptions) error, 0, 2)
		if httpClient != nil {
			loadOptions = append(loadOptions, awsconfig.WithHTTPClient(httpClient))
		}
		region := strings.TrimSpace(options.Region)
		if region == "" {
			region = profile.AWSRegion
		}
		if region != "" {
			loadOptions = append(loadOptions, awsconfig.WithRegion(region))
		}
		loaded, loadErr := awsconfig.LoadDefaultConfig(normalizeContext(options.Context), loadOptions...)
		if loadErr != nil {
			return aws.Config{}, loadErr
		}
		config = loaded
	}
	if region := strings.TrimSpace(options.Region); region != "" {
		config.Region = region
	} else if config.Region == "" && profile.AWSRegion != "" {
		config.Region = profile.AWSRegion
	}
	if config.Region == "" {
		return aws.Config{}, ErrProviderValidation
	}
	// Do not allow SDK request/credential logging to be enabled through a
	// configuration object supplied to this provider.
	config.ClientLogMode = 0
	baseEndpoint := strings.TrimSpace(options.BaseEndpoint)
	if baseEndpoint == "" && profile.Provider == "bedrock" {
		baseEndpoint = strings.TrimSpace(profile.Endpoint)
	}
	if baseEndpoint != "" {
		config.BaseEndpoint = aws.String(baseEndpoint)
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: profile.Timeout}
	}
	config.HTTPClient = &boundedAWSHTTPClient{client: config.HTTPClient, limit: profile.MaxResponseBytes}
	return config, nil
}

func classifyAWSConstructionError(provider string, err error) error {
	if errors.Is(err, ErrProviderValidation) {
		return providerError(ProviderErrorValidation, provider, "construction", ErrProviderValidation)
	}
	return providerError(ProviderErrorTransport, provider, "construction", ErrProviderUnavailable)
}

func nativeAWSHTTPClient(timeout time.Duration, options AWSProviderOptions) (aws.HTTPClient, error) {
	if options.HTTPClient != nil && options.Transport != nil {
		return nil, ErrProviderValidation
	}
	if options.HTTPClient != nil {
		return options.HTTPClient, nil
	}
	if options.Transport != nil {
		return &http.Client{Transport: options.Transport, Timeout: timeout}, nil
	}
	return nil, nil
}

var errAWSResponseTooLarge = errors.New("aws provider response exceeds limit")

type boundedAWSHTTPClient struct {
	client aws.HTTPClient
	limit  int
}

func (c *boundedAWSHTTPClient) Do(request *http.Request) (*http.Response, error) {
	response, err := c.client.Do(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	response.Body = &boundedAWSResponseBody{
		ReadCloser: response.Body,
		remaining:  c.limit + 1,
	}
	return response, nil
}

type boundedAWSResponseBody struct {
	io.ReadCloser
	remaining int
}

func (b *boundedAWSResponseBody) Read(value []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errAWSResponseTooLarge
	}
	if len(value) > b.remaining {
		value = value[:b.remaining]
	}
	read, err := b.ReadCloser.Read(value)
	b.remaining -= read
	return read, err
}

func (p *BedrockProvider) Name() string {
	if p == nil {
		return "Amazon Bedrock"
	}
	return p.redactor.SanitizeText("Amazon Bedrock (" + p.profile.Model + ")")
}

func (p *BedrockProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if p == nil || issue == nil {
		err := providerError(ProviderErrorValidation, p.Name(), "diagnose", ErrProviderValidation)
		observeProviderError(ctx, "bedrock", "diagnose", err)
		return nil, err
	}
	raw, err := p.send(ctx, BuildPromptWithSecrets(issue, p.secretValues...))
	if err != nil {
		observeProviderError(ctx, p.Name(), "diagnose", err)
		return nil, err
	}
	diagnosis, err := ParseDiagnosisJSON(raw, issue.ID, p.Name(), p.secretValues...)
	if err != nil {
		observeProviderError(ctx, p.Name(), "diagnose", err)
		return nil, providerError(ProviderErrorResponse, p.Name(), "diagnose", ErrProviderResponse)
	}
	return diagnosis, nil
}

func (p *BedrockProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	if p == nil {
		err := providerError(ProviderErrorValidation, "bedrock", "explain", ErrProviderValidation)
		observeProviderError(ctx, "bedrock", "explain", err)
		return "", err
	}
	query = p.redactor.SanitizeText(query)
	content := query
	if issue != nil {
		content = "Cluster Anomaly Context:\n" + BuildPromptWithSecrets(issue, p.secretValues...) + "\n\nUser Question:\n" + query
	}
	reply, err := p.send(ctx, content)
	if err != nil {
		observeProviderError(ctx, p.Name(), "explain", err)
	}
	return reply, err
}

func (p *BedrockProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	provider := p.Name()
	redactor := sanitizer.DefaultRedactor()
	requestLimit := defaultMaxRequestBytes
	responseLimit := maxProviderResponseBytes
	if p != nil {
		redactor = p.redactor
		requestLimit = p.profile.MaxRequestBytes
		responseLimit = p.profile.MaxResponseBytes
	}
	ctx, prepared, err := prepareStructuredTask(ctx, provider, task, redactor, requestLimit, responseLimit)
	if err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	err = structuredTaskUnsupported(provider, StructuredTask{Operation: prepared.Operation})
	observeProviderError(ctx, provider, prepared.Operation, err)
	return StructuredTaskResult{}, err
}

func (p *BedrockProvider) send(ctx context.Context, prompt string) (string, error) {
	if p == nil || p.client == nil {
		return "", providerError(ProviderErrorValidation, "bedrock", "invoke", ErrProviderValidation)
	}
	requestContext, cancel := context.WithTimeout(normalizeContext(ctx), p.profile.Timeout)
	defer cancel()
	if err := checkProviderContext(requestContext); err != nil {
		return "", classifyAWSProviderError(err, p.Name(), "invoke", requestContext)
	}
	body, err := buildBedrockPayload(p.profile, p.redactor.SanitizeText(prompt))
	if err != nil {
		return "", providerError(ProviderErrorResponse, p.Name(), "invoke", ErrProviderResponse)
	}
	if len(body) > p.profile.MaxRequestBytes {
		return "", providerError(ProviderErrorLimit, p.Name(), "invoke", ErrProviderResponseTooLarge)
	}
	output, err := p.client.InvokeModel(requestContext, &bedrockruntime.InvokeModelInput{
		ModelId:     aws.String(p.profile.Model),
		Accept:      aws.String(awsProviderAccept),
		Body:        body,
		ContentType: aws.String(awsProviderContentType),
	})
	if err != nil {
		return "", classifyAWSProviderError(err, p.Name(), "invoke", requestContext)
	}
	if output == nil || len(output.Body) == 0 {
		return "", providerError(ProviderErrorResponse, p.Name(), "invoke", ErrProviderResponse)
	}
	if len(output.Body) > p.profile.MaxResponseBytes {
		return "", providerError(ProviderErrorLimit, p.Name(), "invoke", ErrProviderResponseTooLarge)
	}
	text, err := extractAWSProviderText(output.Body)
	if err != nil || strings.TrimSpace(text) == "" {
		return "", providerError(ProviderErrorResponse, p.Name(), "invoke", ErrProviderResponse)
	}
	observeProviderUsage(requestContext, p.Name(), "invoke", extractCloudUsage(output.Body))
	return p.redactor.SanitizeText(text), nil
}

func (p *SageMakerProvider) Name() string {
	if p == nil {
		return "Amazon SageMaker"
	}
	return p.redactor.SanitizeText("Amazon SageMaker (" + p.profile.Endpoint + ")")
}

func (p *SageMakerProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if p == nil || issue == nil {
		err := providerError(ProviderErrorValidation, p.Name(), "diagnose", ErrProviderValidation)
		observeProviderError(ctx, "sagemaker", "diagnose", err)
		return nil, err
	}
	raw, err := p.send(ctx, BuildPromptWithSecrets(issue, p.secretValues...))
	if err != nil {
		observeProviderError(ctx, p.Name(), "diagnose", err)
		return nil, err
	}
	diagnosis, err := ParseDiagnosisJSON(raw, issue.ID, p.Name(), p.secretValues...)
	if err != nil {
		observeProviderError(ctx, p.Name(), "diagnose", err)
		return nil, providerError(ProviderErrorResponse, p.Name(), "diagnose", ErrProviderResponse)
	}
	return diagnosis, nil
}

func (p *SageMakerProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	if p == nil {
		err := providerError(ProviderErrorValidation, "sagemaker", "explain", ErrProviderValidation)
		observeProviderError(ctx, "sagemaker", "explain", err)
		return "", err
	}
	query = p.redactor.SanitizeText(query)
	content := query
	if issue != nil {
		content = "Cluster Anomaly Context:\n" + BuildPromptWithSecrets(issue, p.secretValues...) + "\n\nUser Question:\n" + query
	}
	reply, err := p.send(ctx, content)
	if err != nil {
		observeProviderError(ctx, p.Name(), "explain", err)
	}
	return reply, err
}

func (p *SageMakerProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	provider := p.Name()
	redactor := sanitizer.DefaultRedactor()
	requestLimit := defaultMaxRequestBytes
	responseLimit := maxProviderResponseBytes
	if p != nil {
		redactor = p.redactor
		requestLimit = p.profile.MaxRequestBytes
		responseLimit = p.profile.MaxResponseBytes
	}
	ctx, prepared, err := prepareStructuredTask(ctx, provider, task, redactor, requestLimit, responseLimit)
	if err != nil {
		observeProviderError(ctx, provider, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	err = structuredTaskUnsupported(provider, StructuredTask{Operation: prepared.Operation})
	observeProviderError(ctx, provider, prepared.Operation, err)
	return StructuredTaskResult{}, err
}

func (p *SageMakerProvider) send(ctx context.Context, prompt string) (string, error) {
	if p == nil || p.client == nil {
		return "", providerError(ProviderErrorValidation, "sagemaker", "invoke", ErrProviderValidation)
	}
	requestContext, cancel := context.WithTimeout(normalizeContext(ctx), p.profile.Timeout)
	defer cancel()
	if err := checkProviderContext(requestContext); err != nil {
		return "", classifyAWSProviderError(err, p.Name(), "invoke", requestContext)
	}
	body, err := buildSageMakerPayload(p.profile, p.redactor.SanitizeText(prompt))
	if err != nil {
		return "", providerError(ProviderErrorResponse, p.Name(), "invoke", ErrProviderResponse)
	}
	if len(body) > p.profile.MaxRequestBytes {
		return "", providerError(ProviderErrorLimit, p.Name(), "invoke", ErrProviderResponseTooLarge)
	}
	input := &sagemakerruntime.InvokeEndpointInput{
		EndpointName: aws.String(p.profile.Endpoint),
		Accept:       aws.String(awsProviderAccept),
		Body:         body,
		ContentType:  aws.String(awsProviderContentType),
	}
	if p.targetModel != "" {
		input.TargetModel = aws.String(p.targetModel)
	}
	output, err := p.client.InvokeEndpoint(requestContext, input)
	if err != nil {
		return "", classifyAWSProviderError(err, p.Name(), "invoke", requestContext)
	}
	if output == nil || len(output.Body) == 0 {
		return "", providerError(ProviderErrorResponse, p.Name(), "invoke", ErrProviderResponse)
	}
	if len(output.Body) > p.profile.MaxResponseBytes {
		return "", providerError(ProviderErrorLimit, p.Name(), "invoke", ErrProviderResponseTooLarge)
	}
	text, err := extractAWSProviderText(output.Body)
	if err != nil || strings.TrimSpace(text) == "" {
		return "", providerError(ProviderErrorResponse, p.Name(), "invoke", ErrProviderResponse)
	}
	observeProviderUsage(requestContext, p.Name(), "invoke", extractCloudUsage(output.Body))
	return p.redactor.SanitizeText(text), nil
}

func classifyAWSProviderError(err error, provider, operation string, ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return providerError(ProviderErrorTimeout, provider, operation, context.DeadlineExceeded)
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return providerError(ProviderErrorCanceled, provider, operation, context.Canceled)
	}
	return providerError(ProviderErrorTransport, provider, operation, ErrProviderUnavailable)
}

func buildBedrockPayload(profile ProviderProfile, prompt string) ([]byte, error) {
	model := strings.ToLower(profile.Model)
	var payload interface{}
	switch {
	case strings.Contains(model, "anthropic.claude-3"), strings.Contains(model, "anthropic.claude-3-5"), strings.Contains(model, "anthropic.claude-3-7"), strings.Contains(model, "anthropic.claude-4"):
		payload = map[string]interface{}{
			"anthropic_version": "bedrock-2023-05-31",
			"max_tokens":        profile.MaxTokens,
			"messages": []interface{}{map[string]interface{}{
				"role":    "user",
				"content": []interface{}{map[string]string{"type": "text", "text": prompt}},
			}},
		}
		addAnthropicOptions(payload.(map[string]interface{}), profile)
	case strings.Contains(model, "anthropic.claude"):
		payload = map[string]interface{}{
			"prompt":               "\n\nHuman: " + prompt + "\n\nAssistant:",
			"max_tokens_to_sample": profile.MaxTokens,
		}
		addLegacyTextOptions(payload.(map[string]interface{}), profile)
	case strings.HasPrefix(model, "amazon.nova"):
		inference := map[string]interface{}{"maxTokens": profile.MaxTokens}
		addNovaOptions(inference, profile)
		payload = map[string]interface{}{
			"messages": []interface{}{map[string]interface{}{
				"role":    "user",
				"content": []interface{}{map[string]string{"text": prompt}},
			}},
			"inferenceConfig": inference,
		}
	case strings.HasPrefix(model, "amazon.titan"):
		generation := map[string]interface{}{"maxTokenCount": profile.MaxTokens}
		addTitanOptions(generation, profile)
		payload = map[string]interface{}{"inputText": prompt, "textGenerationConfig": generation}
	case strings.HasPrefix(model, "cohere.command"):
		payload = map[string]interface{}{"prompt": prompt, "max_tokens": profile.MaxTokens}
		addCohereOptions(payload.(map[string]interface{}), profile)
	case strings.Contains(model, "meta.llama"):
		payload = map[string]interface{}{"prompt": prompt, "max_gen_len": profile.MaxTokens}
		addLlamaOptions(payload.(map[string]interface{}), profile)
	case strings.HasPrefix(model, "mistral."):
		payload = map[string]interface{}{"prompt": prompt, "max_tokens": profile.MaxTokens}
		addMistralOptions(payload.(map[string]interface{}), profile)
	default:
		payload = map[string]interface{}{"prompt": prompt, "max_tokens": profile.MaxTokens}
		addLegacyTextOptions(payload.(map[string]interface{}), profile)
	}
	return json.Marshal(payload)
}

func buildSageMakerPayload(profile ProviderProfile, prompt string) ([]byte, error) {
	parameters := map[string]interface{}{"max_new_tokens": profile.MaxTokens}
	if profile.TemperatureSet || profile.Temperature != 0 {
		parameters["temperature"] = profile.Temperature
	}
	if profile.TopPSet || profile.TopP != 0 {
		parameters["top_p"] = profile.TopP
	}
	if len(profile.Stop) > 0 {
		parameters["stop"] = append([]string(nil), profile.Stop...)
	}
	return json.Marshal(map[string]interface{}{"inputs": prompt, "parameters": parameters})
}

func addAnthropicOptions(payload map[string]interface{}, profile ProviderProfile) {
	if profile.TemperatureSet || profile.Temperature != 0 {
		payload["temperature"] = profile.Temperature
	}
	if profile.TopPSet || profile.TopP != 0 {
		payload["top_p"] = profile.TopP
	}
	if len(profile.Stop) > 0 {
		payload["stop_sequences"] = append([]string(nil), profile.Stop...)
	}
}

func addLegacyTextOptions(payload map[string]interface{}, profile ProviderProfile) {
	if profile.TemperatureSet || profile.Temperature != 0 {
		payload["temperature"] = profile.Temperature
	}
	if profile.TopPSet || profile.TopP != 0 {
		payload["top_p"] = profile.TopP
	}
	if len(profile.Stop) > 0 {
		payload["stop_sequences"] = append([]string(nil), profile.Stop...)
	}
}

func addNovaOptions(payload map[string]interface{}, profile ProviderProfile) {
	if profile.TemperatureSet || profile.Temperature != 0 {
		payload["temperature"] = profile.Temperature
	}
	if profile.TopPSet || profile.TopP != 0 {
		payload["topP"] = profile.TopP
	}
	if len(profile.Stop) > 0 {
		payload["stopSequences"] = append([]string(nil), profile.Stop...)
	}
}

func addTitanOptions(payload map[string]interface{}, profile ProviderProfile) {
	if profile.TemperatureSet || profile.Temperature != 0 {
		payload["temperature"] = profile.Temperature
	}
	if profile.TopPSet || profile.TopP != 0 {
		payload["topP"] = profile.TopP
	}
	if len(profile.Stop) > 0 {
		payload["stopSequences"] = append([]string(nil), profile.Stop...)
	}
}

func addCohereOptions(payload map[string]interface{}, profile ProviderProfile) {
	if profile.TemperatureSet || profile.Temperature != 0 {
		payload["temperature"] = profile.Temperature
	}
	if profile.TopPSet || profile.TopP != 0 {
		payload["p"] = profile.TopP
	}
	if len(profile.Stop) > 0 {
		payload["stop_sequences"] = append([]string(nil), profile.Stop...)
	}
}

func addLlamaOptions(payload map[string]interface{}, profile ProviderProfile) {
	if profile.TemperatureSet || profile.Temperature != 0 {
		payload["temperature"] = profile.Temperature
	}
	if profile.TopPSet || profile.TopP != 0 {
		payload["top_p"] = profile.TopP
	}
}

func addMistralOptions(payload map[string]interface{}, profile ProviderProfile) {
	if profile.TemperatureSet || profile.Temperature != 0 {
		payload["temperature"] = profile.Temperature
	}
	if profile.TopPSet || profile.TopP != 0 {
		payload["top_p"] = profile.TopP
	}
	if len(profile.Stop) > 0 {
		payload["stop"] = append([]string(nil), profile.Stop...)
	}
}

func extractAWSProviderText(body []byte) (string, error) {
	if len(body) == 0 || !utf8.Valid(body) {
		return "", ErrProviderResponse
	}
	var value interface{}
	if err := json.Unmarshal(body, &value); err != nil {
		text := strings.TrimSpace(string(body))
		if text == "" {
			return "", ErrProviderResponse
		}
		return text, nil
	}
	if isDiagnosisResponse(value) {
		return strings.TrimSpace(string(body)), nil
	}
	if text, ok := findAWSProviderText(value); ok {
		return text, nil
	}
	return "", ErrProviderResponse
}

func isDiagnosisResponse(value interface{}) bool {
	object, ok := value.(map[string]interface{})
	if !ok {
		return false
	}
	_, issueID := object["issue_id"]
	_, summary := object["summary"]
	_, rootCause := object["root_cause"]
	return issueID && (summary || rootCause)
}

func findAWSProviderText(value interface{}) (string, bool) {
	switch typed := value.(type) {
	case string:
		text := strings.TrimSpace(typed)
		return text, text != ""
	case []interface{}:
		for _, item := range typed {
			if text, ok := findAWSProviderText(item); ok {
				return text, true
			}
		}
	case map[string]interface{}:
		for _, key := range []string{"outputText", "generated_text", "generation", "output_text", "completion", "text", "response", "prediction", "content", "result"} {
			if item, ok := typed[key]; ok {
				if text, ok := findAWSProviderText(item); ok {
					return text, true
				}
			}
		}
		for _, key := range []string{"choices", "candidates", "outputs", "results", "generations", "predictions", "message", "parts", "data", "body"} {
			if item, ok := typed[key]; ok {
				if text, ok := findAWSProviderText(item); ok {
					return text, true
				}
			}
		}
	}
	return "", false
}
