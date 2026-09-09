package feedback

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"testing"
	"time"
)

func TestFeedbackCommitsDisputeAndPreservesHistory(t *testing.T) {
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
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "engineer", Role: authorization.Investigator}})
	principal := identity.Principal{ID: "reviewer", Issuer: "https://idp", Groups: []string{"engineer"}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)}
	item := incident.Item{Scope: scope, IncidentID: "incident", ID: "evidence", Version: 1, Kind: incident.Evidence, Body: json.RawMessage(`{"code":"POD_FAILED"}`), ObservedAt: time.Now().Add(-time.Minute), ValidUntil: time.Now().Add(time.Hour)}
	item.Seal()
	err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.PutItem(item)
	})
	if err != nil {
		t.Fatal(err)
	}
	service := Service{DB: db, Policy: policy}
	request := Request{IncidentID: "incident", Item: incident.ItemRef{ID: item.ID, Version: 1}, ItemHash: item.Hash, Assessment: incident.False, IdempotencyKey: "first", ReasonCode: "FACTUAL_ERROR"}
	event, err := service.Submit(ctx, principal, scope, request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := service.Submit(ctx, principal, scope, request)
	if err != nil || again.ID != event.ID {
		t.Fatal("feedback idempotence failed")
	}
	request.Assessment = incident.True
	if _, err = service.Submit(ctx, principal, scope, request); !errors.Is(err, postgres.ErrConflict) {
		t.Fatalf("conflicting key accepted: %v", err)
	}
	request.IdempotencyKey = "revision"
	request.Supersedes = event.ID
	if _, err = service.Submit(ctx, principal, scope, request); err != nil {
		t.Fatal(err)
	}
	err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		eligible, err := tx.Eligible(request.Item, time.Now())
		if eligible {
			t.Fatal("True automatically removed dispute")
		}
		events, err := tx.FeedbackHistory(request.Item, 100)
		if err != nil {
			return err
		}
		if len(events) != 2 {
			t.Fatal("feedback overwritten")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	other := scope
	other.ClusterID = "other"
	if _, err = service.Submit(ctx, principal, other, request); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatal("cross-scope feedback accepted")
	}
	request.ItemHash = "stale"
	request.IdempotencyKey = "stale"
	if _, err = service.Submit(ctx, principal, scope, request); err == nil {
		t.Fatal("stale hash accepted")
	}
}
