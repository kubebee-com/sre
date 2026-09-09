package postgres

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/incident"
	"testing"
	"time"
)

func TestDiagnosticLeaseUsesCurrentClockWithinTransaction(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	scope := testScope()
	a := incident.Agent{Scope: scope, ID: "agent", Role: "COLLECTOR", Generation: 1, Epoch: "epoch"}
	var lease DiagnosticLease
	if err := db.Transact(ctx, scope, func(tx *Tx) error {
		if err := tx.CreateIncident(testIncident(scope)); err != nil {
			return err
		}
		j := incident.DiagnosticJob{Scope: scope, ID: "job", IncidentID: "incident", ProfileID: "profile", ActorID: "human", State: "QUEUED", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
		if err := tx.PutDiagnosticJob(j, "authority"); err != nil {
			return err
		}
		var err error
		lease, err = tx.ClaimAgentDiagnostic(a, []string{"profile"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A transaction can begin before a lease expires, then wait on another operation.
	// Its fixed transaction timestamp must not permit renewing expired ownership.
	err := db.Transact(ctx, scope, func(tx *Tx) error {
		if _, err := tx.db.Exec(ctx, `UPDATE enterprise_core.diagnostic_jobs SET lease_until=clock_timestamp()+interval '20 milliseconds' WHERE `+scopeWhere, tx.args()...); err != nil {
			return err
		}
		if _, err := tx.db.Exec(ctx, `SELECT pg_sleep(0.04)`); err != nil {
			return err
		}
		_, err := tx.AgentDiagnostic("job", lease.AttemptID, a, true)
		return err
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired lease renewed using transaction timestamp: %v", err)
	}
}
