package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/cache"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

const (
	cachedDiagnosePromptSchema = "triage-diagnose-v1"
	cachedExplainPromptSchema  = "triage-explain-v1"
)

type cacheBypassContextKey struct{}

// WithCacheBypass returns a context that tells CachedProvider to skip cache
// lookup and storage for the current request. Context values, deadlines, and
// cancellation are preserved for the underlying provider.
func WithCacheBypass(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, cacheBypassContextKey{}, true)
}

func cacheBypassed(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	bypassed, _ := ctx.Value(cacheBypassContextKey{}).(bool)
	return bypassed
}

// CachedDiagnosePromptSchema identifies the prompt contract used for cached
// diagnosis results.
const CachedDiagnosePromptSchema = cachedDiagnosePromptSchema

// CachedExplainPromptSchema identifies the prompt contract used for cached
// explanation results.
const CachedExplainPromptSchema = cachedExplainPromptSchema

// CachedProviderOption configures a CachedProvider. The decorator is opt-in:
// callers must explicitly construct it with a cache implementation.
type CachedProviderOption func(*cachedProviderOptions) error

type cachedProviderOptions struct {
	model           string
	endpoint        string
	wireAPI         WireAPI
	redactionSchema string
	secretValues    []string
	ttl             time.Duration
}

// WithCachedProviderModel adds the model identity to the semantic cache key.
func WithCachedProviderModel(model string) CachedProviderOption {
	return func(options *cachedProviderOptions) error {
		options.model = strings.TrimSpace(model)
		return nil
	}
}

// WithCachedProviderEndpoint adds the endpoint identity to the semantic cache
// key. The value is redacted before it is used by the key builder.
func WithCachedProviderEndpoint(endpoint string) CachedProviderOption {
	return func(options *cachedProviderOptions) error {
		options.endpoint = strings.TrimSpace(endpoint)
		return nil
	}
}

// WithCachedProviderWireAPI adds the provider wire contract to the semantic
// cache identity so chat and Responses results cannot collide.
func WithCachedProviderWireAPI(wireAPI WireAPI) CachedProviderOption {
	return func(options *cachedProviderOptions) error {
		wireAPI = WireAPI(strings.ToLower(strings.TrimSpace(string(wireAPI))))
		switch wireAPI {
		case WireAPIChat, WireAPIResponses:
			options.wireAPI = wireAPI
			return nil
		default:
			return ErrProviderValidation
		}
	}
}

// WithCachedProviderRedactionSchema pins the redaction policy used to build
// cache identity. A policy change must invalidate prior provider results.
func WithCachedProviderRedactionSchema(schema string) CachedProviderOption {
	return func(options *cachedProviderOptions) error {
		schema = strings.TrimSpace(schema)
		if schema == "" || len(schema) > 128 || strings.ContainsAny(schema, "\r\n\x00") {
			return ErrProviderValidation
		}
		options.redactionSchema = schema
		return nil
	}
}

// WithCachedProviderSecrets supplies literal secrets that must be removed from
// prompts, provider identity fields, and cached result values.
func WithCachedProviderSecrets(secretValues ...string) CachedProviderOption {
	return func(options *cachedProviderOptions) error {
		for _, secret := range secretValues {
			if secret != "" {
				options.secretValues = append(options.secretValues, secret)
			}
		}
		return nil
	}
}

// WithCachedProviderTTL applies an explicit TTL to values written by the
// decorator. Zero delegates TTL selection to the cache implementation.
func WithCachedProviderTTL(ttl time.Duration) CachedProviderOption {
	return func(options *cachedProviderOptions) error {
		if ttl < 0 {
			return fmt.Errorf("cached provider ttl must not be negative")
		}
		options.ttl = ttl
		return nil
	}
}

// CachedProvider decorates a TriageProvider with opt-in, best-effort result
// caching. Its configuration is immutable after construction.
type CachedProvider struct {
	provider        TriageProvider
	resultCache     cache.Cache
	name            string
	model           string
	endpoint        string
	wireAPI         WireAPI
	redactionSchema string
	secretValues    []string
	redactor        *sanitizer.Redactor
	ttl             time.Duration
}

// CachedTriageProvider is an explicit name for the provider decorator.
type CachedTriageProvider = CachedProvider

var _ TriageProvider = (*CachedProvider)(nil)

// NewCachedProvider constructs a provider decorator. Cache failures are
// deliberately best-effort so an unavailable cache cannot hide provider
// results or provider errors.
func NewCachedProvider(provider TriageProvider, resultCache cache.Cache, options ...CachedProviderOption) (*CachedProvider, error) {
	if provider == nil {
		return nil, errors.New("cached provider requires a provider")
	}
	if resultCache == nil {
		return nil, errors.New("cached provider requires a cache")
	}

	configured := cachedProviderOptions{}
	for _, option := range options {
		if option == nil {
			continue
		}
		if err := option(&configured); err != nil {
			return nil, err
		}
	}
	secrets := append([]string(nil), configured.secretValues...)
	redactor := sanitizer.RedactorForSecrets(secrets...)
	name := strings.TrimSpace(redactor.SanitizeText(provider.Name()))
	if name == "" {
		return nil, errors.New("cached provider requires a provider name")
	}
	providerModel, providerEndpoint := providerCacheIdentity(provider)
	if configured.model == "" {
		configured.model = providerModel
	}
	if configured.endpoint == "" {
		configured.endpoint = providerEndpoint
	}
	wireAPI := configured.wireAPI
	if wireAPI == "" {
		wireAPI = providerWireAPI(provider)
	}
	if wireAPI == "" {
		wireAPI = WireAPIChat
	}
	redactionSchema := configured.redactionSchema
	if redactionSchema == "" {
		redactionSchema = sanitizer.RedactionSchema
	}

	return &CachedProvider{
		provider:        provider,
		resultCache:     resultCache,
		name:            name,
		model:           configured.model,
		endpoint:        configured.endpoint,
		wireAPI:         wireAPI,
		redactionSchema: redactionSchema,
		secretValues:    secrets,
		redactor:        redactor,
		ttl:             configured.ttl,
	}, nil
}

// NewCachedTriageProvider is an alias for NewCachedProvider.
func NewCachedTriageProvider(provider TriageProvider, resultCache cache.Cache, options ...CachedProviderOption) (*CachedProvider, error) {
	return NewCachedProvider(provider, resultCache, options...)
}

func (p *CachedProvider) Name() string {
	if p == nil {
		return ""
	}
	return p.name
}

func (p *CachedProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if p == nil || p.provider == nil {
		return nil, errors.New("cached provider is not initialized")
	}
	bypassCache := cacheBypassed(ctx)
	var key cache.CacheKey
	if !bypassCache {
		key = p.semanticKey(cachedDiagnosePromptSchema, BuildPromptWithSecrets(issue, p.secretValues...))
		if value, found := p.lookup(ctx, key); found {
			if diagnosis, ok := decodeCachedDiagnosis(value); ok && p.validDiagnosis(diagnosis, issue) {
				return p.safeDiagnosis(diagnosis), nil
			}
		}
	}

	diagnosis, err := p.provider.Diagnose(ctx, issue)
	if err != nil {
		return nil, err
	}
	if diagnosis == nil {
		return nil, nil
	}
	if err := p.validateDiagnosis(diagnosis, issue); err != nil {
		return nil, err
	}
	defensive := p.safeDiagnosis(diagnosis)
	if !bypassCache {
		if encoded, encodeErr := json.Marshal(defensive); encodeErr == nil {
			p.store(ctx, key, encoded)
		}
	}
	return cloneDiagnosis(defensive), nil
}

func (p *CachedProvider) validDiagnosis(diagnosis *Diagnosis, issue *scanner.Issue) bool {
	return p.validateDiagnosis(diagnosis, issue) == nil
}

func (p *CachedProvider) validateDiagnosis(diagnosis *Diagnosis, issue *scanner.Issue) error {
	expectedIssueID := ""
	if issue != nil {
		expectedIssueID = issue.ID
	}
	return validateDiagnosis(diagnosis, expectedIssueID, p.redactor)
}

func (p *CachedProvider) Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error) {
	if p == nil || p.provider == nil {
		return "", errors.New("cached provider is not initialized")
	}
	bypassCache := cacheBypassed(ctx)
	var key cache.CacheKey
	if !bypassCache {
		key = p.semanticKey(cachedExplainPromptSchema, p.explainPrompt(query, issue))
		if value, found := p.lookup(ctx, key); found {
			var explanation string
			if err := json.Unmarshal(value, &explanation); err == nil {
				return p.redactor.SanitizeText(explanation), nil
			}
		}
	}

	explanation, err := p.provider.Explain(ctx, query, issue)
	if err != nil {
		return "", err
	}
	explanation = p.redactor.SanitizeText(explanation)
	if !bypassCache {
		if encoded, encodeErr := json.Marshal(explanation); encodeErr == nil {
			p.store(ctx, key, encoded)
		}
	}
	return explanation, nil
}

func (p *CachedProvider) RunStructured(ctx context.Context, task StructuredTask) (StructuredTaskResult, error) {
	if p == nil || p.provider == nil {
		return StructuredTaskResult{}, errors.New("cached provider is not initialized")
	}
	requestLimit, responseLimit := structuredTaskProviderLimits(p.provider)
	ctx, prepared, err := prepareStructuredTask(ctx, p.name, task, p.redactor, requestLimit, responseLimit)
	if err != nil {
		observeProviderError(ctx, p.name, safeStructuredTaskOperationLabel(task.Operation), err)
		return StructuredTaskResult{}, err
	}
	runner, ok := p.provider.(StructuredTaskRunner)
	if !ok {
		err := structuredTaskUnsupported(p.name, StructuredTask{Operation: prepared.Operation})
		observeProviderError(ctx, p.name, prepared.Operation, err)
		return StructuredTaskResult{}, err
	}
	result, err := runner.RunStructured(ctx, StructuredTask{
		Operation:      prepared.Operation,
		SystemPrompt:   prepared.SystemPrompt,
		UserPrompt:     prepared.UserPrompt,
		MaxOutputBytes: prepared.MaxOutputBytes,
	})
	if err != nil {
		return StructuredTaskResult{}, err
	}
	return finalizeStructuredTaskResult(p.name, prepared, result, p.redactor)
}

func (p *CachedProvider) semanticKey(schema, prompt string) cache.CacheKey {
	operation := "explain"
	if schema == cachedDiagnosePromptSchema {
		operation = "diagnose"
	}
	sanitizedPrompt := p.redactor.SanitizeText(prompt)
	return cache.NewSemanticCacheKey(
		operation,
		p.redactor.SanitizeText(p.name),
		p.redactor.SanitizeText(p.model),
		p.redactor.SanitizeText(p.endpoint),
		string(p.wireAPI),
		p.redactor.SanitizeText(schema),
		p.redactionSchema,
		"",
		sanitizedPrompt,
	)
}

func providerWireAPI(provider TriageProvider) WireAPI {
	switch typed := provider.(type) {
	case *OpenAICompatibleProvider:
		return typed.profile.WireAPI
	case *CloudProvider:
		return typed.profile.WireAPI
	case *BedrockProvider:
		return typed.profile.WireAPI
	case *SageMakerProvider:
		return typed.profile.WireAPI
	default:
		return WireAPIChat
	}
}

func providerCacheIdentity(provider TriageProvider) (string, string) {
	switch typed := provider.(type) {
	case *OpenAICompatibleProvider:
		return typed.profile.Model, typed.endpoint
	case *CloudProvider:
		return typed.profile.Model, typed.endpoint
	case *BedrockProvider:
		return typed.profile.Model, typed.profile.Endpoint
	case *SageMakerProvider:
		return typed.profile.Model, typed.profile.Endpoint
	case *ClaudeProvider:
		return typed.model, typed.baseURL
	case *CodexProvider:
		return typed.model, typed.baseURL
	case *DeepSeekProvider:
		if typed.codex != nil {
			return typed.codex.model, typed.codex.baseURL
		}
	}
	return "", ""
}

type cachedExplainPrompt struct {
	Query string `json:"query"`
	Issue string `json:"issue_prompt,omitempty"`
}

func (p *CachedProvider) explainPrompt(query string, issue *scanner.Issue) string {
	prompt := cachedExplainPrompt{
		Query: p.redactor.SanitizeText(query),
	}
	if issue != nil {
		prompt.Issue = BuildPromptWithSecrets(issue, p.secretValues...)
	}
	encoded, err := json.Marshal(prompt)
	if err != nil {
		return prompt.Query
	}
	return string(encoded)
}

func (p *CachedProvider) lookup(ctx context.Context, key cache.CacheKey) ([]byte, bool) {
	value, found, err := p.resultCache.Lookup(ctx, key)
	if err != nil || !found || errors.Is(err, cache.ErrCacheMiss) {
		return nil, false
	}
	return append([]byte(nil), value...), true
}

func (p *CachedProvider) store(ctx context.Context, key cache.CacheKey, value []byte) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	if p.ttl > 0 {
		_ = p.resultCache.Set(ctx, key, append([]byte(nil), value...), p.ttl)
		return
	}
	_ = p.resultCache.Set(ctx, key, append([]byte(nil), value...))
}

func decodeCachedDiagnosis(value []byte) (*Diagnosis, bool) {
	var diagnosis *Diagnosis
	if len(value) == 0 || len(value) > maxProviderResponseBytes || json.Unmarshal(value, &diagnosis) != nil || diagnosis == nil {
		return nil, false
	}
	return diagnosis, true
}

func (p *CachedProvider) safeDiagnosis(diagnosis *Diagnosis) *Diagnosis {
	if diagnosis == nil {
		return nil
	}
	return diagnosis.SanitizedWithRedactor(p.redactor).AsDiagnosis()
}

func cloneDiagnosis(diagnosis *Diagnosis) *Diagnosis {
	if diagnosis == nil {
		return nil
	}
	copy := *diagnosis
	copy.TargetReplicas = cloneInt32Pointer(diagnosis.TargetReplicas)
	return &copy
}
