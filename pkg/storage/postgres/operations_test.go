package postgres

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"os"
	"testing"
	"time"
)

func TestOperationsScopeAndTransientRetention(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	b := a
	b.ApplicationID = "b"
	for _, scope := range []identity.Scope{a, b} {
		if err := db.Transact(ctx, scope, func(tx *Tx) error {
			if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
				return err
			}
			if err := tx.PutItem(incident.Item{Scope: scope, IncidentID: "i", ID: "e", Version: 1, Kind: incident.Evidence, Body: json.RawMessage(`{"code":"HEALTHY"}`), ObservedAt: time.Now().Add(-time.Hour), ValidUntil: time.Now().Add(time.Hour)}); err != nil {
				return err
			}
			if err := tx.Enqueue("report", "COLLECTOR_REPORT", json.RawMessage(`{"report_hash":"opaque"}`)); err != nil {
				return err
			}
			_, err := tx.db.Exec(tx.ctx, `UPDATE enterprise_core.outbox SET created_at=now()-interval '100 days' WHERE `+scopeWhere, tx.args()...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Transact(ctx, a, func(tx *Tx) error {
		if err := tx.Quarantine(incident.ItemRef{ID: "e", Version: 1}); err != nil {
			return err
		}
		return tx.Retain(90)
	}); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []identity.Scope{a, b} {
		if err := db.Transact(ctx, scope, func(tx *Tx) error {
			result, err := tx.OperationalSnapshot(time.Now())
			if err != nil {
				return err
			}
			want := int64(0)
			if scope == a {
				want = 1
			}
			if result.QuarantinedItems != want || result.FreshEvidence != 1 {
				t.Fatal("cross-scope operations counts", result)
			}
			var count int
			if err := tx.db.QueryRow(tx.ctx, `SELECT count(*) FROM enterprise_core.outbox WHERE `+scopeWhere, tx.args()...).Scan(&count); err != nil {
				return err
			}
			if (scope == a && count != 0) || (scope == b && count != 1) {
				t.Fatal("retention crossed scope", count)
			}
			_, err = tx.Item(incident.ItemRef{ID: "e", Version: 1})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEscalationProgressesBeyondFirstPage(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	if err := db.Transact(ctx, scope, func(tx *Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		for n := 0; n < 51; n++ {
			if err := tx.Enqueue(identity.NewID(), "INCIDENT_CREATED", json.RawMessage(`{"incident_id":"i"}`)); err != nil {
				return err
			}
		}
		for n := 0; n < 2; n++ {
			if err := tx.MaterializeNotifications("primary"); err != nil {
				return err
			}
		}
		if _, err := tx.db.Exec(tx.ctx, `UPDATE enterprise_core.notifications SET state='DELIVERED',created_at=now()-interval '2 hours' WHERE `+scopeWhere, tx.args()...); err != nil {
			return err
		}
		for n := 0; n < 2; n++ {
			if err := tx.EscalateNotifications("primary", "escalation", time.Minute); err != nil {
				return err
			}
		}
		var count int
		err := tx.db.QueryRow(tx.ctx, `SELECT count(*) FROM enterprise_core.notifications WHERE `+scopeWhere+` AND route_id='escalation'`, tx.args()...).Scan(&count)
		if err == nil && count != 51 {
			t.Fatal("escalation starved beyond first page", count)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNewEscalationRouteDoesNotReplayHistory(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	db, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	err = db.Transact(context.Background(), scope, func(tx *Tx) error {
		if err := tx.RegisterNotificationRoute("primary"); err != nil {
			return err
		}
		if err := tx.Enqueue("old", "INCIDENT_CREATED", json.RawMessage(`{"incident_id":"i"}`)); err != nil {
			return err
		}
		if err := tx.MaterializeNotifications("primary"); err != nil {
			return err
		}
		if _, err := tx.db.Exec(tx.ctx, `UPDATE enterprise_core.outbox SET created_at=now()-interval '2 hours' WHERE `+scopeWhere, tx.args()...); err != nil {
			return err
		}
		if err := tx.RegisterNotificationRoute("new"); err != nil {
			return err
		}
		if err := tx.Enqueue("fresh", "INCIDENT_CREATED", json.RawMessage(`{"incident_id":"i"}`)); err != nil {
			return err
		}
		if err := tx.MaterializeNotifications("primary"); err != nil {
			return err
		}
		if _, err := tx.db.Exec(tx.ctx, `UPDATE enterprise_core.notifications SET state='DELIVERED',created_at=now()-interval '2 hours' WHERE `+scopeWhere, tx.args()...); err != nil {
			return err
		}
		if err := tx.EscalateNotifications("primary", "new", time.Minute); err != nil {
			return err
		}
		var count int
		if err := tx.db.QueryRow(tx.ctx, `SELECT count(*) FROM enterprise_core.notifications WHERE `+scopeWhere+` AND route_id='new'`, tx.args()...).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatalf("expected only fresh event, got %d", count)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
