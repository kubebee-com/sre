package execution

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReconcileRequiresOwnerAuthorityBeforeStorage(t *testing.T) {
	scope := identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "investigator", Role: authorization.Investigator}, {Scope: scope, Group: "owner", Role: authorization.Owner}})
	s := Service{Enabled: true, Fleet: &fleet.Service{Policy: policy}}
	p := identity.Principal{ID: "engineer", Issuer: "https://idp", Groups: []string{"investigator"}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	if _, e := s.Reconcile(context.Background(), p, scope, "action", strings.Repeat("a", 64)); !errors.Is(e, authorization.ErrForbidden) {
		t.Fatal(e)
	}
	p.Groups = []string{"owner"}
	scope.ApplicationID = "other"
	if _, e := s.Reconcile(context.Background(), p, scope, "action", strings.Repeat("a", 64)); !errors.Is(e, authorization.ErrForbidden) {
		t.Fatal(e)
	}
}
func TestReconcileLostReceiptAndConcurrentReceipt(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, e := postgres.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owner", Role: authorization.Owner}, {Scope: scope, Group: "approver", Role: authorization.Approver}, {Scope: scope, Group: "admin", Role: authorization.Administrator}})
	principal := func(group string) identity.Principal {
		return identity.Principal{ID: group, Issuer: "https://idp", Groups: []string{group}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	}
	f, _ := fleet.NewService(db, policy, "epoch")
	b, e := f.Bootstrap(ctx, principal("admin"), scope, "executor", "cluster", fleet.Executor)
	if e != nil {
		t.Fatal(e)
	}
	c, e := f.Enroll(ctx, scope, b.Token, "cluster", fleet.Executor)
	if e != nil {
		t.Fatal(e)
	}
	s := Service{Fleet: f, Enabled: true}
	receipt := strings.Repeat("r", 64)
	if e = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		return tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()})
	}); e != nil {
		t.Fatal(e)
	}
	seed := func(age time.Duration, state string) incident.Action {
		t.Helper()
		p := incident.ActionPlan{Scope: scope, ID: identity.NewID(), IncidentID: "incident", Kind: "REPLACE_POD", ExecutorID: c.Agent.ID, ExecutorGeneration: c.Agent.Generation, Epoch: f.Epoch, ExpiresAt: time.Now().Add(-time.Minute)}
		a := incident.Action{Plan: p, Hash: p.Hash(), State: state, Version: 1, SubmittedAt: time.Now().Add(-age), ApprovedBy: "owner", CreatedAt: time.Now().Add(-time.Hour)}
		if e := db.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.SaveAction(a, 0, fleet.TokenHash(receipt)) }); e != nil {
			t.Fatal(e)
		}
		return a
	}
	for _, tc := range []struct {
		name        string
		age         time.Duration
		state, hash string
	}{{"premature", 119 * time.Second, "SUBMITTED", ""}, {"wrong-hash", 3 * time.Minute, "SUBMITTED", strings.Repeat("0", 64)}, {"approved", 3 * time.Minute, "APPROVED", ""}, {"applied", 3 * time.Minute, "APPLIED", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			a := seed(tc.age, tc.state)
			hash := a.Hash
			if tc.hash != "" {
				hash = tc.hash
			}
			if _, e := s.Reconcile(ctx, principal("owner"), scope, a.Plan.ID, hash); !errors.Is(e, postgres.ErrConflict) {
				t.Fatalf("accepted invalid reconciliation: %v", e)
			}
		})
	}
	a := seed(3*time.Minute, "SUBMITTED")
	done, e := s.Reconcile(ctx, principal("approver"), scope, a.Plan.ID, a.Hash)
	if e != nil || done.State != "AMBIGUOUS" || done.OutcomeCode != "AMBIGUOUS" || done.ReconciledBy != "approver" || done.Version != 2 || done.CompletedAt.IsZero() {
		t.Fatalf("bad terminal reconciliation: %+v %v", done, e)
	}
	conn, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(ctx)
	var prior, current, attributed, notifications int
	e = conn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE version=1 AND envelope->>'state'='SUBMITTED'),count(*) FILTER (WHERE version=2 AND envelope->>'state'='AMBIGUOUS'),count(*) FILTER (WHERE version=2 AND envelope->>'reconciled_by'='approver') FROM enterprise_core.action_events WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND action_id=$4`, scope.OrganizationID, scope.ClusterID, scope.ApplicationID, a.Plan.ID).Scan(&prior, &current, &attributed)
	if e != nil || prior != 1 || current != 1 || attributed != 1 {
		t.Fatalf("action history not preserved: %d %d %d %v", prior, current, attributed, e)
	}
	e = conn.QueryRow(ctx, `SELECT count(*) FROM enterprise_core.outbox WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND payload->>'action_id'=$4 AND payload->>'state'='AMBIGUOUS'`, scope.OrganizationID, scope.ClusterID, scope.ApplicationID, a.Plan.ID).Scan(&notifications)
	if e != nil || notifications != 1 {
		t.Fatal("reconciliation outbox missing", e)
	}
	if late, err := s.Receipt(ctx, scope, c.Token, a.Plan.ID, receipt, "APPLIED"); err != nil || late.State != "AMBIGUOUS" || late.Version != 2 || late.ReconciledBy != "approver" {
		t.Fatal("late receipt must acknowledge unchanged owner reconciliation", late, err)
	}
	if _, err := s.Receipt(ctx, scope, c.Token, a.Plan.ID, strings.Repeat("x", 64), "APPLIED"); !errors.Is(err, postgres.ErrConflict) {
		t.Fatal("reconciliation bypassed receipt authentication", err)
	}
	if _, e = s.Approve(ctx, principal("owner"), scope, a.Plan.ID, a.Hash); !errors.Is(e, postgres.ErrConflict) {
		t.Fatal("reapproved ambiguous action", e)
	}
	if _, e = s.Claim(ctx, scope, c.Token, a.Plan.ID); !errors.Is(e, postgres.ErrConflict) {
		t.Fatal("replayed ambiguous action", e)
	}
	for i := 0; i < 8; i++ {
		a := seed(3*time.Minute, "SUBMITTED")
		var reconcileErr, receiptErr error
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		go func() {
			defer wg.Done()
			<-start
			_, reconcileErr = s.Reconcile(ctx, principal("owner"), scope, a.Plan.ID, a.Hash)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, receiptErr = s.Receipt(ctx, scope, c.Token, a.Plan.ID, receipt, "APPLIED")
		}()
		close(start)
		wg.Wait()
		if receiptErr != nil || (reconcileErr != nil && !errors.Is(reconcileErr, postgres.ErrConflict)) {
			t.Fatalf("expected one transition winner: %v %v", reconcileErr, receiptErr)
		}
		if e := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
			final, _, e := tx.Action(a.Plan.ID)
			if e != nil {
				return e
			}
			if final.Version != 2 || (final.State != "APPLIED" && final.State != "AMBIGUOUS") {
				t.Fatal("race corrupted final action")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
}
