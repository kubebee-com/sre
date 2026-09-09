package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func database(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SRE_ENTERPRISE_TEST_DATABASE_URL is not set; real PostgreSQL contract not executed")
	}
	s, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
func testScope() identity.Scope {
	return identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
}
func testIncident(s identity.Scope) incident.Incident {
	return incident.Incident{Scope: s, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now().UTC()}
}
func testItem(s identity.Scope, id string, parents ...incident.ItemRef) incident.Item {
	return incident.Item{Scope: s, IncidentID: "incident", ID: id, Version: 1, Kind: incident.Evidence, Body: json.RawMessage(`{"code":"POD_FAILED"}`), ObservedAt: time.Now().UTC().Add(-time.Minute), ValidUntil: time.Now().UTC().Add(time.Hour), Parents: parents}
}
func TestPostgresScopeImmutabilityAndLineage(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	a, b := testScope(), testScope()
	ref := incident.ItemRef{ID: "e", Version: 1}
	if err := db.Transact(ctx, a, func(tx *Tx) error {
		if err := tx.CreateIncident(testIncident(a)); err != nil {
			return err
		}
		return tx.PutItem(testItem(a, "e"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, b, func(tx *Tx) error {
		if err := tx.CreateIncident(testIncident(b)); err != nil {
			return err
		}
		return tx.PutItem(testItem(b, "child", ref))
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cross-scope reference: %v", err)
	}
	if err := db.Transact(ctx, b, func(tx *Tx) error { _, err := tx.Incident("incident"); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback leaked incident: %v", err)
	}
	if err := db.Transact(ctx, a, func(tx *Tx) error { return tx.PutItem(testItem(a, "e")) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("immutable overwrite: %v", err)
	}
	if err := db.Transact(ctx, a, func(tx *Tx) error { return tx.PutItem(testItem(a, "child", ref)) }); err != nil {
		t.Fatal(err)
	}
	child := incident.ItemRef{ID: "child", Version: 1}
	if err := db.Transact(ctx, a, func(tx *Tx) error {
		eligible, err := tx.Eligible(child, time.Now())
		if err != nil {
			return err
		}
		if !eligible {
			t.Fatal("fresh child ineligible")
		}
		if err := tx.Quarantine(ref); err != nil {
			return err
		}
		eligible, err = tx.Eligible(child, time.Now())
		if eligible {
			t.Fatal("ancestor quarantine not synchronous")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, b, func(tx *Tx) error { _, err := tx.Item(ref); return err }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope read: %v", err)
	}
}
func TestPostgresConcurrentVersionsAndOutboxRollback(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	scope := testScope()
	if err := db.Transact(ctx, scope, func(tx *Tx) error { return tx.CreateIncident(testIncident(scope)) }); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.Transact(ctx, scope, func(tx *Tx) error { return tx.UpdateIncident("incident", 1, "INVESTIGATING") })
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("update: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("version winners %d", wins.Load())
	}
	abort := errors.New("abort")
	err := db.Transact(ctx, scope, func(tx *Tx) error {
		if err := tx.Enqueue("event", "INCIDENT_CHANGED", json.RawMessage(`{"revision":1}`)); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	// A rolled-back key can be reused with different content; committed keys cannot.
	if err := db.Transact(ctx, scope, func(tx *Tx) error { return tx.Enqueue("event", "INCIDENT_CHANGED", json.RawMessage(`{"revision":2}`)) }); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *Tx) error { return tx.Enqueue("event", "INCIDENT_CHANGED", json.RawMessage(`{"revision":2}`)) }); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *Tx) error { return tx.Enqueue("event", "INCIDENT_CHANGED", json.RawMessage(`{"revision":3}`)) }); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting outbox key: %v", err)
	}
}
func TestPostgresRestartFreshnessAndPagination(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	scope := testScope()
	if err := db.Transact(ctx, scope, func(tx *Tx) error {
		if err := tx.CreateIncident(testIncident(scope)); err != nil {
			return err
		}
		for _, id := range []string{"a", "b", "c"} {
			item := testItem(scope, id)
			item.ObservedAt = time.Now().Add(-2 * time.Hour)
			item.ValidUntil = time.Now().Add(-time.Hour)
			if err := tx.PutItem(item); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	other := database(t)
	if err := other.Transact(ctx, scope, func(tx *Tx) error {
		items, err := tx.Items("incident", "a", 1)
		if err != nil {
			return err
		}
		if len(items) != 1 || items[0].ID != "b" {
			t.Fatalf("pagination: %#v", items)
		}
		ok, err := tx.Eligible(incident.ItemRef{ID: "a", Version: 1}, time.Now())
		if ok {
			t.Fatal("expired evidence eligible")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSchemaCompatibilityAndBoundedReads(t *testing.T) {
	base := database(t)
	name := "sre_schema_" + identity.NewID()
	if _, err := base.pool.Exec(context.Background(), "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	config := base.pool.Config().ConnConfig.Copy()
	config.Database = name
	db, err := Open(context.Background(), config.ConnString())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		base.pool.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})
	ctx := context.Background()
	scope := testScope()
	if err := db.Transact(ctx, scope, func(tx *Tx) error { _, err := tx.Items("incident", "", 101); return err }); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbounded read accepted: %v", err)
	}
	if _, err := db.pool.Exec(ctx, "INSERT INTO enterprise_core.migrations(version,checksum) VALUES(999,'future')"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.pool.Exec(context.Background(), "DELETE FROM enterprise_core.migrations WHERE version=999") })
	reopened, err := Open(ctx, config.ConnString())
	if err == nil {
		reopened.Close()
		t.Fatal("future schema silently accepted")
	}
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("future schema: %v", err)
	}
	if _, err = db.pool.Exec(ctx, "DELETE FROM enterprise_core.migrations WHERE version=999"); err != nil {
		t.Fatal(err)
	}
	var checksum string
	if err = db.pool.QueryRow(ctx, "SELECT checksum FROM enterprise_core.migrations WHERE version=1").Scan(&checksum); err != nil {
		t.Fatal(err)
	}
	if _, err = db.pool.Exec(ctx, "UPDATE enterprise_core.migrations SET checksum='changed' WHERE version=1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.pool.Exec(context.Background(), "UPDATE enterprise_core.migrations SET checksum=$1 WHERE version=1", checksum)
	})
	reopened, err = Open(ctx, config.ConnString())
	if err == nil {
		reopened.Close()
		t.Fatal("changed schema silently accepted")
	}
}
