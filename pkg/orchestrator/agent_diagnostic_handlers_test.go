package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestAgentDiagnosticHTTPRequiresCurrentCollectorAndFencesCancellation(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "team", Role: authorization.Administrator}, {Scope: scope, Group: "team", Role: authorization.Investigator}})
	human := identity.Principal{ID: "human", Issuer: "https://idp", Groups: []string{"team"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	f, err := fleet.NewService(db, policy, "agent-test-epoch")
	if err != nil {
		t.Fatal(err)
	}
	creds := map[string]fleet.Credential{}
	for _, role := range []string{fleet.Collector, fleet.Executor} {
		boot, err := f.Bootstrap(ctx, human, scope, role, "cluster-uid", role)
		if err != nil {
			t.Fatal(err)
		}
		cred, err := f.Enroll(ctx, scope, boot.Token, "cluster-uid", role)
		if err != nil {
			t.Fatal(err)
		}
		creds[role] = cred
	}
	if err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		return tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	service, _ := investigation.NewService(db, policy, []investigation.Profile{{ID: "rule", Version: "v1", Scopes: []identity.Scope{scope}, Metadata: investigation.ProviderMetadata{Provider: "rule"}}})
	queue := &investigation.Queue{Service: service}
	job, err := queue.Enqueue(ctx, human, scope, "incident", "rule")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{DB: db, Policy: policy, Fleet: f, Queue: queue, Investigations: service, Verifier: verifierFunc(func(context.Context, string) (identity.Principal, error) { return human, nil }), PublicURL: "https://sre.example"})
	if err != nil {
		t.Fatal(err)
	}
	query := "?organization_id=" + scope.OrganizationID + "&cluster_id=cluster&application_id=app"
	post := func(path, token string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path+query, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, req)
		return response
	}
	for _, token := range []string{"human-token", creds[fleet.Executor].Token} {
		res := post("/agent/diagnostics/claim", token, map[string]any{"profiles": []string{"rule"}})
		if res.Code != 401 {
			t.Fatalf("wrong capability: %d %s", res.Code, res.Body.String())
		}
	}
	res := post("/agent/diagnostics/claim", creds[fleet.Collector].Token, map[string]any{"profiles": []string{"rule"}})
	var claim investigation.AgentClaim
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &claim) != nil || claim.Input.JobID != job.ID {
		t.Fatalf("claim: %d %s", res.Code, res.Body.String())
	}
	if err = queue.Cancel(ctx, human, scope, job.ID); err != nil {
		t.Fatal(err)
	}
	res = post("/agent/diagnostics/"+job.ID+"/heartbeat", creds[fleet.Collector].Token, map[string]string{"attempt_id": claim.AttemptID})
	if res.Code != 404 {
		t.Fatalf("cancel heartbeat: %d %s", res.Code, res.Body.String())
	}
	result := investigation.RunResult{RunID: job.ID, ProfileID: "rule", ProfileVersion: "v1", PrivacyVersion: privacy.Version, PromptVersion: investigation.PromptVersion, RubricVersion: investigation.RubricVersion, Assessment: investigation.Assessment{Status: investigation.NeedsEvidence, ReasonCode: "NO_CURRENT_ELIGIBLE_EVIDENCE"}}
	res = post("/agent/diagnostics/"+job.ID+"/complete", creds[fleet.Collector].Token, map[string]any{"attempt_id": claim.AttemptID, "result": result})
	if res.Code != 404 {
		t.Fatalf("cancel completion: %d %s", res.Code, res.Body.String())
	}
}
