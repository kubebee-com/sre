package investigation

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"github.com/kubebee-com/sre/pkg/triage"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAgentSharedRoundsRejectSelfCorroborationAndRawOutput(t *testing.T) {
	now := time.Now()
	h := strings.Repeat("a", 32)
	state := Snapshot{Evidence: []EvidenceSnapshot{{Ref: incident.ItemRef{ID: "e", Version: 1}, Observation: privacy.Observation{Code: privacy.ResourcePressure, ResourceHandle: h, ObservedAt: now, ValidUntil: now.Add(time.Minute)}}}}
	runner := taskRunnerFunc(func(_ context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
		return triage.StructuredTaskResult{Text: `{"cause_code":"RESOURCE_PRESSURE","resource_handle":"` + h + `","supporting_evidence":[{"id":"e","version":1}],"contradicting_evidence":[],"alternatives":[],"raw_secret":"secret"}`}, nil
	})
	assessment, rounds, _, err := ExecuteRounds(context.Background(), runner, state, nil, nil)
	if err != nil || assessment.Status != Inconclusive || assessment.ReasonCode != "INVALID_PROVIDER_OUTPUT" || len(rounds) != 1 {
		t.Fatal(assessment, err)
	}
}

func TestCompletedResultReassessedWithoutTrustingAgentStatus(t *testing.T) {
	now := time.Now()
	h := strings.Repeat("a", 32)
	state := Snapshot{Evidence: []EvidenceSnapshot{{Ref: incident.ItemRef{ID: "e", Version: 1}, Observation: privacy.Observation{Code: privacy.ResourcePressure, ResourceHandle: h, ObservedAt: now, ValidUntil: now.Add(time.Minute)}}}}
	result := RunResult{Assessment: Assessment{Status: Corroborated, ReasonCode: "AGENT_SAYS_YES", Conclusion: Conclusion{CauseCode: privacy.ResourcePressure, ResourceHandle: h, SupportingEvidence: []incident.ItemRef{{ID: "e", Version: 1}}}}}
	assessed, err := ValidateAgentResult(result, state, now)
	if err != nil || assessed.Status != Hypothesis {
		t.Fatal(assessed, err)
	}
	result.Assessment.Conclusion.SupportingEvidence[0].ID = "forged"
	if _, err = ValidateAgentResult(result, state, now); err == nil {
		t.Fatal("forged citation accepted")
	}
}

func TestAgentCompletionRejectsChangedEvidenceInPostgres(t *testing.T) {
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
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "team", Role: authorization.Investigator}})
	principal := identity.Principal{ID: "human", Issuer: "https://idp", Groups: []string{"team"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	now := time.Now().UTC()
	h := strings.Repeat("a", 32)
	obs := privacy.Observation{Code: privacy.ResourcePressure, ResourceHandle: h, ObservedAt: now, ValidUntil: now.Add(time.Minute)}
	body, _ := json.Marshal(obs)
	item := incident.Item{Scope: scope, IncidentID: "incident", ID: "e", Version: 1, Kind: incident.Evidence, Body: body, ObservedAt: now, ValidUntil: obs.ValidUntil}
	err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: now}); err != nil {
			return err
		}
		return tx.PutItem(item)
	})
	if err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(db, policy, []Profile{{ID: "profile", Version: "v1", Scopes: []identity.Scope{scope}, Runner: taskRunnerFunc(func(context.Context, triage.StructuredTask) (triage.StructuredTaskResult, error) {
		t.Fatal("orchestrator ran inference")
		return triage.StructuredTaskResult{}, nil
	})}})
	q := Queue{Service: service}
	job, err := q.Enqueue(ctx, principal, scope, "incident", "profile")
	if err != nil {
		t.Fatal(err)
	}
	agent := incident.Agent{Scope: scope, ID: "agent", Role: "COLLECTOR", Generation: 1, Epoch: "epoch"}
	auth := func(*postgres.Tx) (incident.Agent, error) { return agent, nil }
	claim, err := q.ClaimAgent(ctx, scope, auth, []string{"profile"})
	if err != nil || claim == nil {
		t.Fatal("claim", err)
	}
	result := RunResult{RunID: job.ID, ProfileID: "profile", ProfileVersion: "v1", PrivacyVersion: privacy.Version, PromptVersion: PromptVersion, RubricVersion: RubricVersion, Assessment: Assessment{Status: Corroborated, Conclusion: Conclusion{CauseCode: privacy.ResourcePressure, ResourceHandle: h, SupportingEvidence: []incident.ItemRef{{ID: "e", Version: 1}}}}}
	// A new contradictory observation is current even if the originally cited item
	// remains fresh. Completion cannot omit it from the independent rubric.
	obs.Code = privacy.Healthy
	body, _ = json.Marshal(obs)
	item.ID = "healthy"
	item.Body = body
	if err = db.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.PutItem(item) }); err != nil {
		t.Fatal(err)
	}
	if _, err = q.CompleteAgent(ctx, scope, auth, job.ID, claim.AttemptID, result); !errors.Is(err, postgres.ErrConflict) {
		t.Fatalf("stale snapshot accepted: %v", err)
	}
	if err = q.Cancel(ctx, principal, scope, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = q.HeartbeatAgent(ctx, scope, auth, job.ID, claim.AttemptID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cancel did not fence heartbeat: %v", err)
	}
}
