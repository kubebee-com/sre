package postgres

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"testing"
	"time"
)

func TestDiagnosticLeaseFencesExpiredAndCancelledOwners(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	scope := testScope()
	agent := incident.Agent{Scope: scope, ID: "agent", Role: "COLLECTOR", Generation: 1, Epoch: "epoch"}
	var first, second DiagnosticLease
	err := db.Transact(ctx, scope, func(tx *Tx) error {
		if err := tx.CreateIncident(testIncident(scope)); err != nil {
			return err
		}
		j := incident.DiagnosticJob{Scope: scope, ID: "job", IncidentID: "incident", ProfileID: "profile", ActorID: "human", State: "QUEUED", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
		if err := tx.PutDiagnosticJob(j, "authority"); err != nil {
			return err
		}
		var err error
		first, err = tx.ClaimAgentDiagnostic(agent, []string{"profile"})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.AttemptID == "" {
		t.Fatal("missing fence")
	}
	err = db.Transact(ctx, scope, func(tx *Tx) error { _, err := tx.ClaimAgentDiagnostic(agent, []string{"profile"}); return err })
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("duplicate claim: %v", err)
	}
	if err = db.Transact(ctx, scope, func(tx *Tx) error {
		_, err := tx.db.Exec(ctx, `UPDATE enterprise_core.diagnostic_jobs SET lease_until=now()-interval '1 second' WHERE `+scopeWhere, tx.args()...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.Transact(ctx, scope, func(tx *Tx) error {
		var err error
		second, err = tx.ClaimAgentDiagnostic(agent, []string{"profile"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if second.AttemptID == first.AttemptID {
		t.Fatal("lease reused fence")
	}
	if err = db.Transact(ctx, scope, func(tx *Tx) error { _, err := tx.AgentDiagnostic("job", first.AttemptID, agent, true); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale owner accepted: %v", err)
	}
	other := agent
	other.ID = identity.NewID()
	if err = db.Transact(ctx, scope, func(tx *Tx) error { _, err := tx.AgentDiagnostic("job", second.AttemptID, other, true); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong owner accepted: %v", err)
	}
	if err = db.Transact(ctx, scope, func(tx *Tx) error { return tx.FinishDiagnosticJob("job", "CANCELLED", nil) }); err != nil {
		t.Fatal(err)
	}
	if err = db.Transact(ctx, scope, func(tx *Tx) error { _, err := tx.AgentDiagnostic("job", second.AttemptID, agent, true); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancelled owner accepted: %v", err)
	}
}
