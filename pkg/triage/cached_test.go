package triage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/cache"
	"github.com/kubebee-com/sre/pkg/scanner"
)

type cachedProviderTestProvider struct {
	name                string
	diagnosis           *Diagnosis
	explanation         string
	diagnoseErr         error
	explainErr          error
	diagnoseCalls       int
	explainCalls        int
	lastDiagnoseContext context.Context
	lastExplainContext  context.Context
	lastQuery           string
}

func (p *cachedProviderTestProvider) Name() string { return p.name }

func (p *cachedProviderTestProvider) Diagnose(ctx context.Context, _ *scanner.Issue) (*Diagnosis, error) {
	p.diagnoseCalls++
	p.lastDiagnoseContext = ctx
	return p.diagnosis, p.diagnoseErr
}

func (p *cachedProviderTestProvider) Explain(ctx context.Context, query string, _ *scanner.Issue) (string, error) {
	p.explainCalls++
	p.lastExplainContext = ctx
	p.lastQuery = query
	return p.explanation, p.explainErr
}

type cachedProviderTestCache struct {
	values     map[string][]byte
	lookupKeys []cache.CacheKey
	setKeys    []cache.CacheKey
	setTTLs    []time.Duration
	lookupErr  error
	setErr     error
}

func newCachedProviderTestCache() *cachedProviderTestCache {
	return &cachedProviderTestCache{values: make(map[string][]byte)}
}

func (c *cachedProviderTestCache) Get(ctx context.Context, key cache.CacheKey) ([]byte, error) {
	value, found, err := c.Lookup(ctx, key)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, cache.ErrCacheMiss
	}
	return value, nil
}

func (c *cachedProviderTestCache) Set(_ context.Context, key cache.CacheKey, value []byte, ttls ...time.Duration) error {
	c.setKeys = append(c.setKeys, key)
	c.setTTLs = append(c.setTTLs, append([]time.Duration(nil), ttls...)...)
	if c.setErr != nil {
		return c.setErr
	}
	c.values[key.Digest()] = append([]byte(nil), value...)
	return nil
}

func (c *cachedProviderTestCache) Lookup(_ context.Context, key cache.CacheKey) ([]byte, bool, error) {
	c.lookupKeys = append(c.lookupKeys, key)
	if c.lookupErr != nil {
		return nil, false, c.lookupErr
	}
	value, found := c.values[key.Digest()]
	if !found {
		return nil, false, cache.ErrCacheMiss
	}
	return append([]byte(nil), value...), true, nil
}

func (c *cachedProviderTestCache) Remove(_ context.Context, key cache.CacheKey) error {
	delete(c.values, key.Digest())
	return nil
}

func (c *cachedProviderTestCache) List(context.Context) ([]cache.CacheEntry, error) { return nil, nil }

func (c *cachedProviderTestCache) Purge(context.Context) error {
	c.values = make(map[string][]byte)
	return nil
}

func (c *cachedProviderTestCache) Stats() cache.CacheStats { return cache.CacheStats{} }

func TestCachedProviderCachesDiagnoseWithSanitizedSemanticKey(t *testing.T) {
	secret := "triage-secret"
	replicas := int32(3)
	underlyingDiagnosis := &Diagnosis{
		IssueID:         "issue-1",
		Summary:         "pod is unhealthy",
		RootCause:       "container failed",
		Severity:        scanner.SeverityHigh,
		RemediationPlan: "restart the pod",
		ActionType:      ActionRestartPod,
		ProposedCommand: "kubectl get pod example -n default",
		TargetReplicas:  &replicas,
		ConfidenceScore: 0.9,
		ProviderName:    "test-provider",
	}
	provider := &cachedProviderTestProvider{name: "test-provider", diagnosis: underlyingDiagnosis}
	store := newCachedProviderTestCache()
	cached, err := NewCachedProvider(provider, store,
		WithCachedProviderModel("model-"+secret),
		WithCachedProviderEndpoint("https://provider.example/v1?token="+secret),
		WithCachedProviderSecrets(secret),
	)
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}
	var _ TriageProvider = cached

	issue := &scanner.Issue{
		ID:          "issue-1",
		Namespace:   "default",
		Kind:        "Pod",
		Name:        "example",
		Severity:    scanner.SeverityHigh,
		Category:    scanner.CategoryCrashLoop,
		Summary:     "pod contains " + secret,
		Details:     "authorization: " + secret,
		LogsSnippet: "token=" + secret,
	}

	first, err := cached.Diagnose(context.Background(), issue)
	if err != nil {
		t.Fatalf("first Diagnose() error = %v", err)
	}
	if provider.diagnoseCalls != 1 {
		t.Fatalf("underlying Diagnose() calls = %d, want 1", provider.diagnoseCalls)
	}
	if first == underlyingDiagnosis || first.TargetReplicas == underlyingDiagnosis.TargetReplicas {
		t.Fatal("first diagnosis shares mutable state with provider result")
	}
	first.Summary = "caller mutation"
	*first.TargetReplicas = 99

	second, err := cached.Diagnose(context.Background(), issue)
	if err != nil {
		t.Fatalf("cached Diagnose() error = %v", err)
	}
	if provider.diagnoseCalls != 1 {
		t.Fatalf("underlying Diagnose() calls after hit = %d, want 1", provider.diagnoseCalls)
	}
	if second.Summary != underlyingDiagnosis.Summary || second.TargetReplicas == nil || *second.TargetReplicas != 3 {
		t.Fatalf("cached diagnosis was not isolated from caller mutation: %#v", second)
	}
	if second.TargetReplicas == first.TargetReplicas {
		t.Fatal("cached diagnosis shares mutable state with prior result")
	}
	if len(store.setKeys) != 1 {
		t.Fatalf("cache Set() calls = %d, want 1", len(store.setKeys))
	}

	key := store.setKeys[0]
	if key.Provider != "test-provider" {
		t.Errorf("cache key provider = %q, want %q", key.Provider, "test-provider")
	}
	if strings.Contains(key.Model, secret) || strings.Contains(key.Endpoint, secret) {
		t.Fatalf("cache key identity contains raw secret: %#v", key)
	}
	if key.Prompt != "" || strings.Contains(key.PromptHash, secret) {
		t.Fatalf("cache key retains raw prompt material: %#v", key)
	}
	if key.PromptSchema != cachedDiagnosePromptSchema {
		t.Errorf("cache key prompt schema = %q, want %q", key.PromptSchema, cachedDiagnosePromptSchema)
	}
	if key.Operation != "diagnose" || key.WireAPI != string(WireAPIChat) || key.RedactionSchema == "" || key.EvidenceDigest == "" {
		t.Fatalf("cache key omitted semantic identity: %#v", key)
	}
	canonical, err := key.Canonical()
	if err != nil {
		t.Fatalf("cache key Canonical() error = %v", err)
	}
	if strings.Contains(string(canonical), secret) {
		t.Fatalf("canonical cache key contains raw secret: %s", canonical)
	}
	if strings.Contains(string(store.values[key.Digest()]), secret) {
		t.Fatal("cached diagnosis contains raw configured secret")
	}

	expectedPrompt := BuildPromptWithSecrets(issue, secret)
	expectedKey := cache.NewCacheKey("test-provider", "model-"+secret, "https://provider.example/v1?token="+secret, cachedDiagnosePromptSchema, expectedPrompt)
	if key.Digest() == expectedKey.Digest() {
		t.Fatal("cache key was built from unsanitized identity fields")
	}
}

func TestCachedProviderCachesExplainSeparatelyFromDiagnose(t *testing.T) {
	provider := &cachedProviderTestProvider{
		name:        "test-provider",
		diagnosis:   &Diagnosis{IssueID: "issue-2", Summary: "summary", RootCause: "cause", Severity: scanner.SeverityLow, RemediationPlan: "plan", ActionType: ActionManual, ProposedCommand: "kubectl get pods", ConfidenceScore: 0.5, ProviderName: "test-provider"},
		explanation: "explanation",
	}
	store := newCachedProviderTestCache()
	cached, err := NewCachedProvider(provider, store,
		WithCachedProviderModel("model"),
		WithCachedProviderEndpoint("https://provider.example/v1"),
		WithCachedProviderSecrets("query-secret"),
	)
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}
	issue := &scanner.Issue{ID: "issue-2", Namespace: "default", Kind: "Pod", Name: "example", Summary: "summary"}

	if _, err := cached.Diagnose(context.Background(), issue); err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	query := "why did this happen? query-secret"
	first, err := cached.Explain(context.Background(), query, issue)
	if err != nil {
		t.Fatalf("first Explain() error = %v", err)
	}
	second, err := cached.Explain(context.Background(), query, issue)
	if err != nil {
		t.Fatalf("cached Explain() error = %v", err)
	}
	if first != provider.explanation || second != provider.explanation {
		t.Fatalf("Explain() results = %q, %q", first, second)
	}
	if provider.diagnoseCalls != 1 || provider.explainCalls != 1 {
		t.Fatalf("underlying calls = diagnose:%d explain:%d, want 1 each", provider.diagnoseCalls, provider.explainCalls)
	}
	if provider.lastQuery != query {
		t.Fatalf("underlying Explain() query = %q, want original query", provider.lastQuery)
	}
	if len(store.setKeys) != 2 {
		t.Fatalf("cache Set() calls = %d, want 2", len(store.setKeys))
	}
	if store.setKeys[0].PromptSchema != cachedDiagnosePromptSchema || store.setKeys[1].PromptSchema != cachedExplainPromptSchema {
		t.Fatalf("cache schemas = %q, %q", store.setKeys[0].PromptSchema, store.setKeys[1].PromptSchema)
	}
	if store.setKeys[0].Digest() == store.setKeys[1].Digest() {
		t.Fatal("Diagnose and Explain share a cache key")
	}
	canonical, err := store.setKeys[1].Canonical()
	if err != nil {
		t.Fatalf("Explain cache key Canonical() error = %v", err)
	}
	if strings.Contains(string(canonical), "query-secret") {
		t.Fatalf("Explain cache key contains raw query secret: %s", canonical)
	}
}

func TestCachedProviderBypassSkipsLookupAndSetForExplain(t *testing.T) {
	provider := &cachedProviderTestProvider{name: "test-provider", explanation: "fresh explanation"}
	store := newCachedProviderTestCache()
	cached, err := NewCachedProvider(provider, store)
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}

	requestKey := "request-id"
	requestValue := "request-value"
	requestContext := context.WithValue(context.Background(), requestKey, requestValue)
	if _, err := cached.Explain(requestContext, "question", nil); err != nil {
		t.Fatalf("initial Explain() error = %v", err)
	}
	if len(store.lookupKeys) != 1 || len(store.setKeys) != 1 {
		t.Fatalf("initial cache operations = lookup:%d set:%d, want one each", len(store.lookupKeys), len(store.setKeys))
	}

	bypassContext := WithCacheBypass(requestContext)
	reply, err := cached.Explain(bypassContext, "question", nil)
	if err != nil {
		t.Fatalf("bypassed Explain() error = %v", err)
	}
	if reply != provider.explanation {
		t.Fatalf("bypassed Explain() = %q, want %q", reply, provider.explanation)
	}
	if provider.explainCalls != 2 {
		t.Fatalf("underlying Explain() calls = %d, want 2", provider.explainCalls)
	}
	if len(store.lookupKeys) != 1 || len(store.setKeys) != 1 {
		t.Fatalf("bypassed cache operations = lookup:%d set:%d, want unchanged one each", len(store.lookupKeys), len(store.setKeys))
	}
	if got := provider.lastExplainContext.Value(requestKey); got != requestValue {
		t.Fatalf("provider context value = %v, want %q", got, requestValue)
	}
}

func TestCachedProviderBypassSkipsLookupAndSetForDiagnose(t *testing.T) {
	provider := &cachedProviderTestProvider{
		name:      "test-provider",
		diagnosis: &Diagnosis{IssueID: "issue-bypass", Summary: "summary", RootCause: "cause", Severity: scanner.SeverityLow, RemediationPlan: "plan", ActionType: ActionManual, ProposedCommand: "kubectl get pods", ConfidenceScore: 0.5, ProviderName: "test-provider"},
	}
	store := newCachedProviderTestCache()
	cached, err := NewCachedProvider(provider, store)
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}
	issue := &scanner.Issue{ID: "issue-bypass"}
	if _, err := cached.Diagnose(context.Background(), issue); err != nil {
		t.Fatalf("initial Diagnose() error = %v", err)
	}

	if _, err := cached.Diagnose(WithCacheBypass(context.Background()), issue); err != nil {
		t.Fatalf("bypassed Diagnose() error = %v", err)
	}
	if provider.diagnoseCalls != 2 {
		t.Fatalf("underlying Diagnose() calls = %d, want 2", provider.diagnoseCalls)
	}
	if len(store.lookupKeys) != 1 || len(store.setKeys) != 1 {
		t.Fatalf("bypassed cache operations = lookup:%d set:%d, want unchanged one each", len(store.lookupKeys), len(store.setKeys))
	}
}

func TestCachedProviderBypassPreservesProviderError(t *testing.T) {
	providerError := errors.New("provider failure")
	provider := &cachedProviderTestProvider{name: "test-provider", explainErr: providerError}
	store := newCachedProviderTestCache()
	cached, err := NewCachedProvider(provider, store)
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}
	requestKey := "request-id"
	requestValue := "request-value"
	requestContext := context.WithValue(context.Background(), requestKey, requestValue)

	_, err = cached.Explain(WithCacheBypass(requestContext), "question", nil)
	if err != providerError {
		t.Fatalf("bypassed Explain() error = %v, want original provider error", err)
	}
	if len(store.lookupKeys) != 0 || len(store.setKeys) != 0 {
		t.Fatalf("bypassed cache operations = lookup:%d set:%d, want zero", len(store.lookupKeys), len(store.setKeys))
	}
	if got := provider.lastExplainContext.Value(requestKey); got != requestValue {
		t.Fatalf("provider context value = %v, want %q", got, requestValue)
	}
}

func TestCachedProviderTreatsCacheMissAsNormalAndPreservesProviderErrors(t *testing.T) {
	providerError := errors.New("provider failure")
	provider := &cachedProviderTestProvider{name: "test-provider", diagnoseErr: providerError, explainErr: providerError}
	store := newCachedProviderTestCache()
	cached, err := NewCachedProvider(provider, store)
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}

	issue := &scanner.Issue{ID: "issue-3"}
	if _, err := cached.Diagnose(context.Background(), issue); err != providerError {
		t.Fatalf("Diagnose() error = %v, want original provider error", err)
	}
	if _, err := cached.Explain(context.Background(), "question", issue); err != providerError {
		t.Fatalf("Explain() error = %v, want original provider error", err)
	}
	if provider.diagnoseCalls != 1 || provider.explainCalls != 1 {
		t.Fatalf("underlying calls = diagnose:%d explain:%d, want 1 each", provider.diagnoseCalls, provider.explainCalls)
	}
	if len(store.setKeys) != 0 {
		t.Fatalf("cache Set() calls after provider errors = %d, want 0", len(store.setKeys))
	}
}

func TestCachedProviderFallsThroughCacheBackendErrors(t *testing.T) {
	provider := &cachedProviderTestProvider{
		name:      "test-provider",
		diagnosis: &Diagnosis{IssueID: "issue-4", Summary: "summary", RootCause: "cause", Severity: scanner.SeverityLow, RemediationPlan: "plan", ActionType: ActionManual, ProposedCommand: "kubectl get pods", ConfidenceScore: 0.5, ProviderName: "test-provider"},
	}
	store := newCachedProviderTestCache()
	store.lookupErr = errors.New("cache backend unavailable")
	cached, err := NewCachedProvider(provider, store)
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}
	if _, err := cached.Diagnose(context.Background(), &scanner.Issue{ID: "issue-4"}); err != nil {
		t.Fatalf("Diagnose() error = %v, want cache backend failure to be non-fatal", err)
	}
	if provider.diagnoseCalls != 1 {
		t.Fatalf("underlying Diagnose() calls = %d, want 1", provider.diagnoseCalls)
	}
}

func TestCachedProviderRejectsInvalidCachedDiagnosis(t *testing.T) {
	provider := &cachedProviderTestProvider{
		name:      "test-provider",
		diagnosis: &Diagnosis{IssueID: "issue-5", Summary: "summary", RootCause: "cause", Severity: scanner.SeverityLow, RemediationPlan: "plan", ActionType: ActionManual, ProposedCommand: "kubectl get pods", ConfidenceScore: 0.5, ProviderName: "test-provider"},
	}
	store := newCachedProviderTestCache()
	cached, err := NewCachedProvider(provider, store)
	if err != nil {
		t.Fatalf("NewCachedProvider() error = %v", err)
	}
	issue := &scanner.Issue{ID: "issue-5"}
	if _, err := cached.Diagnose(context.Background(), issue); err != nil {
		t.Fatalf("first Diagnose() error = %v", err)
	}
	if len(store.setKeys) != 1 {
		t.Fatalf("cache Set() calls = %d, want 1", len(store.setKeys))
	}
	store.values[store.setKeys[0].Digest()] = []byte(`{"issue_id":"other","summary":"summary","root_cause":"cause","severity":"LOW","remediation_plan":"plan","action_type":"Manual","proposed_command":"kubectl get pods","confidence_score":0.5}`)

	if _, err := cached.Diagnose(context.Background(), issue); err != nil {
		t.Fatalf("Diagnose() after invalid cache error = %v", err)
	}
	if provider.diagnoseCalls != 2 {
		t.Fatalf("underlying Diagnose() calls = %d, want invalid cache to fall through", provider.diagnoseCalls)
	}
}

func TestCachedProviderRejectsMissingDependencies(t *testing.T) {
	provider := &cachedProviderTestProvider{name: "test-provider"}
	if _, err := NewCachedProvider(nil, newCachedProviderTestCache()); err == nil {
		t.Fatal("NewCachedProvider() accepted nil provider")
	}
	if _, err := NewCachedProvider(provider, nil); err == nil {
		t.Fatal("NewCachedProvider() accepted nil cache")
	}
}

func TestCachedProviderTestDiagnosisIsJSONRoundTrippable(t *testing.T) {
	value := &Diagnosis{IssueID: "issue", Summary: "summary", RootCause: "cause", Severity: scanner.SeverityLow, RemediationPlan: "plan", ActionType: ActionManual, ProposedCommand: "kubectl get pods", ConfidenceScore: 0.5, ProviderName: "provider"}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var decoded Diagnosis
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.IssueID != value.IssueID {
		t.Fatalf("decoded issue ID = %q, want %q", decoded.IssueID, value.IssueID)
	}
}
