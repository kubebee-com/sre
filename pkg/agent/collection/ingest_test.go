package collection

import (
	"context"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIngestRequiresCurrentSourceAndPreservesEvidence(t *testing.T) {
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
	f, _ := fleet.NewService(db, policy, "generation")
	boot, err := f.Bootstrap(ctx, admin, scope, "collector", "cluster", fleet.Collector)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := f.Enroll(ctx, scope, boot.Token, "cluster", fleet.Collector)
	if err != nil {
		t.Fatal(err)
	}
	s := Service{Fleet: f}
	at := time.Now().UTC()
	o := privacy.Observation{Code: privacy.Healthy, ResourceHandle: strings.Repeat("a", 32), ObservedAt: at, ValidUntil: at.Add(time.Minute)}
	report := Report{ID: identity.NewID(), ClusterUID: "cluster", ObservedAt: at, Coverage: "COMPLETE", Observations: []privacy.Observation{o}}
	if err := s.Ingest(ctx, scope, cred.Token, report); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		incidents, err := tx.Incidents("", 10)
		if len(incidents) != 0 {
			t.Fatal("healthy report opened incident")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	report.ID = identity.NewID()
	report.Observations[0].Code = privacy.CrashLoop
	if err := s.Ingest(ctx, scope, cred.Token, report); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, scope, cred.Token, report); err != nil {
		t.Fatal("exact retry rejected", err)
	}
	var itemID string
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		incidents, err := tx.Incidents("", 10)
		if err != nil {
			return err
		}
		if len(incidents) != 1 {
			t.Fatal("incident missing")
		}
		items, err := tx.Items(incidents[0].ID, "", 10)
		if err != nil {
			return err
		}
		if len(items) != 1 || items[0].Version != 1 {
			t.Fatal("retry duplicated evidence")
		}
		itemID = items[0].ID
		ok, err := tx.Eligible(incident.ItemRef{ID: items[0].ID, Version: items[0].Version}, time.Now())
		if !ok {
			t.Fatal("current source not eligible", err)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	report.ID = identity.NewID()
	report.Observations = nil
	report.Coverage = "UNAVAILABLE"
	if err := s.Ingest(ctx, scope, cred.Token, report); err != nil {
		t.Fatal(err)
	}
	if err := f.Revoke(ctx, admin, scope, "collector"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, scope, cred.Token, report); err == nil {
		t.Fatal("revoked report accepted")
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		item, err := tx.CurrentItem(itemID)
		if err != nil {
			return err
		}
		ok, err := tx.Eligible(incident.ItemRef{ID: item.ID, Version: item.Version}, time.Now())
		if ok {
			t.Fatal("revoked source still eligible")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReportRejectsDuplicateAndOldObservations(t *testing.T) {
	at := time.Now()
	o := privacy.Observation{Code: privacy.CrashLoop, ResourceHandle: strings.Repeat("b", 32), ObservedAt: at, ValidUntil: at.Add(time.Minute)}
	r := Report{ID: identity.NewID(), ClusterUID: "c", ObservedAt: at, Coverage: "COMPLETE", Observations: []privacy.Observation{o, o}}
	if r.Validate() == nil {
		t.Fatal("duplicate resource/code accepted")
	}
	r.Observations = r.Observations[:1]
	r.Observations[0].ObservedAt = at.Add(-30 * time.Minute)
	if r.Validate() == nil {
		t.Fatal("old evidence disguised as new report")
	}
}
