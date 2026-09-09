package investigation

import (
	"context"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"testing"
	"time"
)

func TestQueuedRunIsDurableDeduplicatedCancellableAndCounted(t *testing.T) {
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
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "team", Role: authorization.Investigator}})
	p := identity.Principal{ID: "engineer", Issuer: "https://idp", Groups: []string{"team"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		return tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(db, policy, []Profile{{ID: "rule", Version: "v1", Scopes: []identity.Scope{scope}}})
	q := Queue{Service: service, Scopes: []identity.Scope{scope}}
	j, err := q.Enqueue(ctx, p, scope, "i", "rule")
	if err != nil {
		t.Fatal(err)
	}
	again, err := q.Enqueue(ctx, p, scope, "i", "rule")
	if err != nil || j.ID != again.ID {
		t.Fatal("duplicate active job")
	}
	auth := func(*postgres.Tx) (incident.Agent, error) {
		return incident.Agent{Scope: scope, ID: "agent", Role: "COLLECTOR", Generation: 1, Epoch: "epoch"}, nil
	}
	claim, err := q.ClaimAgent(ctx, scope, auth, []string{"rule"})
	if err != nil || claim == nil {
		t.Fatal("claim", err)
	}
	_, err = q.CompleteAgent(ctx, scope, auth, j.ID, claim.AttemptID, RunResult{RunID: j.ID, ProfileID: "rule", ProfileVersion: "v1", PrivacyVersion: privacy.Version, PromptVersion: PromptVersion, RubricVersion: RubricVersion, Assessment: Assessment{Status: NeedsEvidence, ReasonCode: "NO_CURRENT_ELIGIBLE_EVIDENCE"}})
	if err != nil {
		t.Fatal("complete", err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		job, err := tx.DiagnosticJob(j.ID)
		if err != nil {
			return err
		}
		if job.State != "COMPLETED" || job.Result == nil {
			t.Fatal("job not durably completed", job.State)
		}
		runs, err := tx.QualityRuns(time.Now().Add(-time.Hour))
		if err != nil {
			return err
		}
		if len(runs) != 1 || runs[0].Status != "NEEDS_EVIDENCE" {
			t.Fatal("accepted attempt denominator", runs)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	j, err = q.Enqueue(ctx, p, scope, "i", "rule")
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Cancel(ctx, p, scope, j.ID); err != nil {
		t.Fatal(err)
	}
	if claim, err := q.ClaimAgent(ctx, scope, auth, []string{"rule"}); err != nil || claim != nil {
		t.Fatal("cancelled job claimed", err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		job, err := tx.DiagnosticJob(j.ID)
		if err != nil {
			return err
		}
		if job.State != "CANCELLED" || job.Result != nil {
			t.Fatal("cancelled job executed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
