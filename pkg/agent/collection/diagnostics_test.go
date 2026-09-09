package collection

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/triage"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type diagnosticRunner func(context.Context, triage.StructuredTask) (triage.StructuredTaskResult, error)

func (f diagnosticRunner) RunStructured(c context.Context, t triage.StructuredTask) (triage.StructuredTaskResult, error) {
	return f(c, t)
}
func TestDiagnosticsUseLocalProviderAndOnlyProjectedCompletion(t *testing.T) {
	cfg, k := runtimeFixture(t)
	var got investigation.RunResult
	completed := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 43) {
			t.Error("wrong credential capability")
		}
		if !strings.HasSuffix(r.URL.Path, "/complete") {
			t.Errorf("unexpected %s", r.URL.Path)
			http.Error(w, "bad", 400)
			return
		}
		var req struct {
			AttemptID string                  `json:"attempt_id"`
			Result    investigation.RunResult `json:"result"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.AttemptID != "attempt" {
			t.Error("missing fence")
		}
		got = req.Result
		completed = true
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	cfg.ControlPlane = server.URL
	r, err := newRuntime(cfg, k, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.credential = testCredential()
	session := r.credential
	r.diagnosticSession.Store(&session)
	now := time.Now()
	handle := strings.Repeat("a", 32)
	claim := investigation.AgentClaim{AttemptID: "attempt", LeaseUntil: now.Add(time.Minute), Input: investigation.AgentInput{Scope: runtimeScope, JobID: "job", ProfileID: "profile", ProfileVersion: "version", Snapshot: investigation.Snapshot{Evidence: []investigation.EvidenceSnapshot{{Ref: incident.ItemRef{ID: "e", Version: 1}, Observation: privacy.Observation{Code: privacy.ResourcePressure, ResourceHandle: handle, ObservedAt: now, ValidUntil: now.Add(time.Minute)}}}}}}
	calls := 0
	resolve := func(investigation.ProviderMetadata) (triage.StructuredTaskRunner, error) {
		return diagnosticRunner(func(_ context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
			calls++
			if strings.Contains(task.UserPrompt, "customer-canary") {
				t.Error("raw namespace leaked")
			}
			return triage.StructuredTaskResult{Text: `{"cause_code":"RESOURCE_PRESSURE","resource_handle":"` + handle + `","supporting_evidence":[{"id":"e","version":1}],"contradicting_evidence":[],"alternatives":[]}`}, nil
		}), nil
	}
	if err = r.runDiagnostic(context.Background(), claim, resolve); err != nil {
		t.Fatal(err)
	}
	if !completed || calls != 3 || got.Assessment.Status != investigation.Hypothesis || got.RunID != "job" {
		t.Fatal("shared agent diagnosis failed", completed, calls, got)
	}
}
