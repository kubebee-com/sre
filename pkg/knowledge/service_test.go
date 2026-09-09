package knowledge

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/recovery"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"strings"
	"testing"
	"time"
)

func TestGoldenPublicationRequiresIndependentReviewAndCurrentLineage(t *testing.T) {
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
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "stewards", Role: authorization.Steward}, {Scope: scope, Group: "admins", Role: authorization.Administrator}})
	principal := func(id, group string) identity.Principal {
		return identity.Principal{ID: id, Issuer: "https://idp", Groups: []string{group}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	}
	f, _ := fleet.NewService(db, policy, "authority")
	boot, err := f.Bootstrap(ctx, principal("admin", "admins"), scope, "collector", "cluster", fleet.Collector)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := f.Enroll(ctx, scope, boot.Token, "cluster", fleet.Collector)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	source := &privacy.Provenance{AgentID: cred.Agent.ID, Generation: cred.Agent.Generation, Epoch: f.Epoch, ReportID: identity.NewID()}
	upstream := strings.Repeat("a", 32)
	healthy := strings.Repeat("b", 32)
	var claim incident.Item
	var assessment incident.RecoveryAssessment
	err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: at.Add(-5 * time.Minute)}); err != nil {
			return err
		}
		evidence := privacy.Observation{Code: privacy.NetworkBlocked, ResourceHandle: upstream, Source: source, ObservedAt: at.Add(-3 * time.Minute), ValidUntil: at.Add(-2 * time.Minute)}
		body, _ := json.Marshal(evidence)
		e := incident.Item{Scope: scope, IncidentID: "i", ID: "cause", Version: 1, Kind: incident.Evidence, Body: body, ObservedAt: evidence.ObservedAt, ValidUntil: evidence.ValidUntil}
		if err := tx.PutItem(e); err != nil {
			return err
		}
		run := struct {
			investigation.RunResult
			StewardID string `json:"steward_id"`
		}{RunResult: investigation.RunResult{RunID: "run", Assessment: investigation.Assessment{Status: investigation.Corroborated, Conclusion: investigation.Conclusion{CauseCode: privacy.NetworkBlocked, ResourceHandle: upstream}}}, StewardID: "independent-steward"}
		raw, _ := json.Marshal(run)
		claim = incident.Item{Scope: scope, IncidentID: "i", ID: "claim", Version: 1, Kind: incident.Claim, Body: raw, ObservedAt: at.Add(-2 * time.Minute), ValidUntil: at.Add(-time.Minute), Parents: []incident.ItemRef{{ID: "cause", Version: 1}}}
		claim.Seal()
		if err := tx.PutItem(claim); err != nil {
			return err
		}
		if err := tx.PutRecoveryProfile(incident.RecoveryProfile{Scope: scope, ID: "application-health", Version: 1, Handles: []string{healthy}, WindowSeconds: 60, MaximumGapSeconds: 35, MinimumSamples: 3, MinimumReadyReplicas: 1}); err != nil {
			return err
		}
		for n := int64(1); n <= 3; n++ {
			when := at.Add(time.Duration(n-3) * 30 * time.Second)
			o := privacy.Observation{Code: privacy.Healthy, ResourceHandle: healthy, Source: source, ObservedAt: when, ValidUntil: when.Add(90 * time.Second)}
			raw, _ := json.Marshal(o)
			ref := incident.ItemRef{ID: "health", Version: n}
			if err := tx.PutItem(incident.Item{Scope: scope, IncidentID: "i", ID: ref.ID, Version: ref.Version, Kind: incident.Evidence, Body: raw, ObservedAt: when, ValidUntil: o.ValidUntil}); err != nil {
				return err
			}
			if err := tx.PutHealthSample(incident.HealthSample{Scope: scope, IncidentID: "i", Evidence: ref, Handle: healthy, UID: "uid", AgentID: source.AgentID, Generation: source.Generation, Epoch: source.Epoch, Coverage: "COMPLETE", Healthy: true, ReadyReplicas: 2, At: when}); err != nil {
				return err
			}
		}
		var err error
		assessment, err = recovery.AssessTx(tx, scope, "i", "application-health", at)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != "RECOVERED" {
		t.Fatal("independent recovery missing", assessment)
	}
	s := Service{DB: db, Policy: policy}
	a := principal("author", "stewards")
	b := principal("reviewer", "stewards")
	g, err := s.Candidate(ctx, a, scope, CandidateRequest{Claim: incident.ItemRef{ID: claim.ID, Version: 1}, ClaimHash: claim.Hash, RecoveryID: assessment.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(ctx, a, scope, g.ID, g.Version); err == nil {
		t.Fatal("self-publication accepted")
	}
	g, err = s.Publish(ctx, b, scope, g.ID, g.Version)
	if err != nil || !g.Evaluation.Approved {
		t.Fatal("reviewed publication", err)
	}
	cases, err := s.Retrieve(ctx, a, scope)
	if err != nil || len(cases) != 1 {
		t.Fatal("published guidance missing", err)
	}

	derived := incident.ItemRef{ID: "derived", Version: 1}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "next-incident", Version: 1, State: "OPEN", OpenedAt: at}); err != nil {
			return err
		}
		raw, _ := json.Marshal(investigation.RunResult{KnowledgeVersions: []incident.ItemRef{{ID: g.ID, Version: g.Version}}})
		if err := tx.PutItem(incident.Item{Scope: scope, IncidentID: "next-incident", ID: derived.ID, Version: 1, Kind: incident.Claim, Body: raw, ObservedAt: at, ValidUntil: at.Add(time.Minute)}); err != nil {
			return err
		}
		eligible, err := tx.Eligible(derived, at)
		if err != nil {
			return err
		}
		if !eligible {
			t.Fatal("historical guidance incorrectly required fresh old observations")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.Quarantine(incident.ItemRef{ID: "cause", Version: 1}) }); err != nil {
		t.Fatal(err)
	}

	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		for _, check := range []func(incident.ItemRef) (bool, error){func(r incident.ItemRef) (bool, error) { return tx.Eligible(r, at) }, tx.Uncontested, tx.HistoricalEligible} {
			ok, err := check(derived)
			if err != nil {
				return err
			}
			if ok {
				t.Fatal("disputed golden source did not invalidate derived claim")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cases, err = s.Retrieve(ctx, a, scope)
	if err != nil || len(cases) != 0 {
		t.Fatal("disputed source polluted retrieval", err)
	}
	if err := f.Revoke(ctx, principal("admin", "admins"), scope, "collector"); err != nil {
		t.Fatal(err)
	}
	boot, err = f.Bootstrap(ctx, principal("admin", "admins"), scope, "collector", "cluster", fleet.Collector)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Enroll(ctx, scope, boot.Token, "cluster", fleet.Collector); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		ok, err := tx.HistoricalEligible(incident.ItemRef{ID: "health", Version: 1})
		if ok {
			t.Fatal("reenrollment resurrected revoked historical source")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
