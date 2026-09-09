package investigation

import (
	"context"
	"encoding/json"
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

type taskRunnerFunc func(context.Context, triage.StructuredTask) (triage.StructuredTaskResult, error)

func (f taskRunnerFunc) RunStructured(ctx context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
	return f(ctx, task)
}
func TestFreshRunExcludesPriorConclusionsAndRejectsConcurrentDispute(t *testing.T) {
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
	principal := identity.Principal{ID: "engineer", Issuer: "https://idp", Groups: []string{"team"}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)}
	observation := privacy.Observation{Code: privacy.NetworkBlocked, ResourceHandle: strings.Repeat("a", 32), ObservedAt: time.Now().Add(-time.Minute), ValidUntil: time.Now().Add(time.Minute)}
	body, _ := json.Marshal(observation)
	item := incident.Item{Scope: scope, IncidentID: "incident", ID: "evidence", Version: 1, Kind: incident.Evidence, Body: body, ObservedAt: observation.ObservedAt, ValidUntil: observation.ValidUntil}
	err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		if err := tx.PutItem(item); err != nil {
			return err
		}
		old := item
		old.ID = "oldclaim"
		old.Kind = incident.Claim
		old.Body = json.RawMessage(`{"wrong_conclusion":"NEVER_REUSE_ME"}`)
		for n := 0; n < 110; n++ {
			old.ID = identity.NewID()
			if err := tx.PutItem(old); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := taskRunnerFunc(func(ctx context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
		if strings.Contains(task.UserPrompt, "NEVER_REUSE_ME") {
			t.Fatal("prior conclusion polluted new run")
		}
		if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.Quarantine(incident.ItemRef{ID: item.ID, Version: 1}) }); err != nil {
			t.Fatal(err)
		}
		return triage.StructuredTaskResult{Text: `{"cause_code":"NETWORK_BLOCKED","resource_handle":"` + observation.ResourceHandle + `","supporting_evidence":[{"id":"evidence","version":1}],"contradicting_evidence":[],"alternatives":[]}`}, nil
	})
	service, err := NewService(db, policy, []Profile{{ID: "approved", Version: "v1", Runner: runner, Scopes: []identity.Scope{scope}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Run(ctx, principal, scope, "incident", "approved"); err != postgres.ErrConflict {
		t.Fatalf("disputed inference persisted: %v", err)
	}
}
