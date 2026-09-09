package quality

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"strings"
	"testing"
	"time"
)

func TestHistoricQualityRejectsRevokedSourcesWithoutRequiringFreshness(t *testing.T) {
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
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "admins", Role: authorization.Administrator}})
	admin := identity.Principal{ID: "admin", Issuer: "https://idp", Groups: []string{"admins"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	f, _ := fleet.NewService(db, policy, "authority")
	boot, err := f.Bootstrap(ctx, admin, scope, "collector", "cluster", fleet.Collector)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := f.Enroll(ctx, scope, boot.Token, "cluster", fleet.Collector)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Hour)
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: at}); err != nil {
			return err
		}
		observation := privacy.Observation{Code: privacy.ResourcePressure, ResourceHandle: strings.Repeat("a", 32), ObservedAt: at, ValidUntil: at.Add(time.Minute), Source: &privacy.Provenance{AgentID: "collector", Generation: credential.Agent.Generation, Epoch: f.Epoch, ReportID: identity.NewID()}}
		body, _ := json.Marshal(observation)
		if err := tx.PutItem(incident.Item{Scope: scope, IncidentID: "i", ID: "e", Version: 1, Kind: incident.Evidence, Body: body, ObservedAt: at, ValidUntil: observation.ValidUntil}); err != nil {
			return err
		}
		raw, _ := json.Marshal(investigation.RunResult{RunID: "r", Assessment: investigation.Assessment{Status: investigation.Corroborated}})
		if err := tx.PutItem(incident.Item{Scope: scope, IncidentID: "i", ID: "claim", Version: 1, Kind: incident.Claim, Body: raw, ObservedAt: at, ValidUntil: at.Add(time.Minute), Parents: []incident.ItemRef{{ID: "e", Version: 1}}}); err != nil {
			return err
		}
		if err := tx.StartRun("r", "i", "profile", "v1", "prompt", "rubric", at); err != nil {
			return err
		}
		return tx.FinishRun("r", "HYPOTHESIS", "", &incident.ItemRef{ID: "claim", Version: 1})
	}); err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
			runs, err := tx.QualityRuns(at.Add(-time.Minute))
			if err == nil && (len(runs) != 1 || runs[0].Invalidated != want) {
				t.Fatal("historical source validity incorrect", runs)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	check(false)
	if err := f.Revoke(ctx, admin, scope, "collector"); err != nil {
		t.Fatal(err)
	}
	check(true)
	boot, err = f.Bootstrap(ctx, admin, scope, "collector", "cluster", fleet.Collector)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Enroll(ctx, scope, boot.Token, "cluster", fleet.Collector); err != nil {
		t.Fatal(err)
	}
	check(true)
}
