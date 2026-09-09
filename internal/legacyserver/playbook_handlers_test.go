package legacyserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/playbook"
	"github.com/kubebee-com/sre/pkg/triage"
)

func playbookRequest(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}
func TestPlaybookRoutesRequireAuthenticationAndExposeDisabledStatus(t *testing.T) {
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{APIToken: testAPIToken})
	for _, path := range []string{"/api/v1/playbooks", "/api/v1/playbooks/status", "/api/v1/playbooks/settings", "/api/v1/playbooks/import", "/api/v1/playbooks/example/approve"} {
		rr := playbookRequest(testHandler(t, s), http.MethodGet, path, "", "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", path, rr.Code)
		}
	}
	rr := playbookRequest(testHandler(t, s), http.MethodGet, "/api/v1/playbooks/status", "", testAPIToken)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"available":false`) {
		t.Fatalf("disabled status: %d %s", rr.Code, rr.Body.String())
	}
	rr = playbookRequest(testHandler(t, s), http.MethodGet, "/api/v1/playbooks", "", testAPIToken)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled catalog: %d", rr.Code)
	}
}
func TestPlaybookStrictRequestsAndSettingsCannotWidenPolicy(t *testing.T) {
	service := playbook.NewService(playbook.NewMemoryCatalog(), nil, playbook.ServiceOptions{Settings: playbook.DefaultServiceSettings()})
	s := NewServer(0, nil, nil, nil, nil, ServerOptions{APIToken: testAPIToken, Playbooks: service, MaxBodyBytes: 1024})
	h := testHandler(t, s)
	if s.PlaybookService() != service {
		t.Fatal("service accessor mismatch")
	}
	for _, body := range []string{`{"content":"hello","media_type":"text/plain","origin":"upload","actor":"forged"}`, `{} {}`, `{"version":1,"state":"ACTIVE"}`} {
		rr := playbookRequest(h, http.MethodPost, "/api/v1/playbooks/import", body, testAPIToken)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("strict import: %d %s", rr.Code, rr.Body.String())
		}
	}
	rr := playbookRequest(h, http.MethodPost, "/api/v1/playbooks/import", `{"content":"`+strings.Repeat("x", 2048)+`"}`, testAPIToken)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("large import: %d", rr.Code)
	}
	settings := service.Settings()
	settings.MinConfidence = 0
	data, _ := json.Marshal(settings)
	rr = playbookRequest(h, http.MethodPut, "/api/v1/playbooks/settings", string(data), testAPIToken)
	if rr.Code != http.StatusBadRequest || service.Settings().MinConfidence == 0 {
		t.Fatalf("widened settings: %d", rr.Code)
	}
	rr = playbookRequest(h, http.MethodGet, "/api/v1/playbooks?limit=999999", "", testAPIToken)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unbounded list: %d", rr.Code)
	}
}
func TestPlaybookListRedactsSecretsAndTransitionsRespectLifecycle(t *testing.T) {
	c := playbook.NewMemoryCatalog(playbook.WithCatalogSecrets("catalog-secret"))
	p := playbook.NormalizedPlaybook{ID: "test", Version: 1, Lifecycle: playbook.LifecycleNormalized, Title: "<script>alert(1)</script>", Summary: "catalog-secret", Confidence: .9, Steps: []playbook.NormalizedStep{{ID: "manual", Order: 1, Action: "Manual", Confidence: .9}}}
	if err := c.SavePlaybook(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	service := playbook.NewService(c, nil, playbook.ServiceOptions{Settings: playbook.DefaultServiceSettings()})
	h := testHandler(t, NewServer(0, nil, nil, nil, nil, ServerOptions{APIToken: testAPIToken, Playbooks: service}))
	rr := playbookRequest(h, http.MethodGet, "/api/v1/playbooks", "", testAPIToken)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "catalog-secret") || strings.Contains(rr.Body.String(), "<script>") {
		t.Fatalf("unsafe list: %d %s", rr.Code, rr.Body.String())
	}
	rr = playbookRequest(h, http.MethodPost, "/api/v1/playbooks/test/reject", `{"version":1}`, testAPIToken)
	if rr.Code != http.StatusConflict {
		t.Fatalf("illegal transition: %d %s", rr.Code, rr.Body.String())
	}
	for _, action := range []string{"review", "reject"} {
		rr = playbookRequest(h, http.MethodPost, "/api/v1/playbooks/test/"+action, `{"version":1}`, testAPIToken)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", action, rr.Code, rr.Body.String())
		}
	}
	rr = playbookRequest(h, http.MethodGet, "/api/v1/playbooks/status", "", testAPIToken)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"token_usage":null`) {
		t.Fatalf("missing unavailable usage: %d %s", rr.Code, rr.Body.String())
	}
}

type playbookAPIRunner struct{}

func (playbookAPIRunner) RunStructured(context.Context, triage.StructuredTask) (triage.StructuredTaskResult, error) {
	return triage.StructuredTaskResult{Text: `{"title":"Inspect","summary":"Inspect pod","confidence":0.9,"steps":[{"id":"inspect","action":"Manual","confidence":0.9}]}`, Usage: triage.ProviderTokenUsage{InputTokens: 11, OutputTokens: 7, TotalTokens: 18}}, nil
}
func TestPlaybookStatusShowsObservedTaskUsage(t *testing.T) {
	service := playbook.NewService(playbook.NewMemoryCatalog(), playbookAPIRunner{}, playbook.ServiceOptions{Settings: playbook.DefaultServiceSettings()})
	h := testHandler(t, NewServer(0, nil, nil, nil, nil, ServerOptions{APIToken: testAPIToken, Playbooks: service}))
	imported := playbookRequest(h, http.MethodPost, "/api/v1/playbooks/import", `{"content":"inspect pod","media_type":"text/markdown","origin":"upload"}`, testAPIToken)
	if imported.Code != http.StatusOK {
		t.Fatalf("import: %d %s", imported.Code, imported.Body.String())
	}
	rr := playbookRequest(h, http.MethodGet, "/api/v1/playbooks/status", "", testAPIToken)
	if !strings.Contains(rr.Body.String(), `"total_tokens":18`) || !strings.Contains(rr.Body.String(), `"calls":1`) {
		t.Fatalf("task usage missing: %s", rr.Body.String())
	}
}

type failingPlaybookCatalog struct{ playbook.Catalog }

func (failingPlaybookCatalog) List(context.Context, int) ([]playbook.NormalizedPlaybook, error) {
	return nil, errors.New("postgres://user:database-password@host/db private-api-key")
}
func TestPlaybookErrorsAndStatusDoNotExposeCredentials(t *testing.T) {
	service := playbook.NewService(failingPlaybookCatalog{playbook.NewMemoryCatalog()}, nil, playbook.ServiceOptions{Settings: playbook.DefaultServiceSettings()})
	h := testHandler(t, NewServer(0, nil, nil, nil, nil, ServerOptions{APIToken: testAPIToken, Playbooks: service, RedactionSecrets: []string{"private-api-key"}, Runtime: RuntimeSettings{LLMModel: "private-api-key"}}))
	for _, path := range []string{"/api/v1/playbooks", "/api/v1/playbooks/status"} {
		rr := playbookRequest(h, http.MethodGet, path, "", testAPIToken)
		for _, secret := range []string{"database-password", "private-api-key"} {
			if strings.Contains(rr.Body.String(), secret) {
				t.Fatalf("%s exposed %s", path, secret)
			}
		}
	}
}
