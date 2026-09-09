package stewardship

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
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

func TestAdjudicationIsScopedImmutableAndDoesNotClearDispute(t *testing.T) {
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
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "stewards", Role: authorization.Steward}})
	p := identity.Principal{ID: "steward", Issuer: "https://idp", Groups: []string{"stewards"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	item := incident.Item{Scope: scope, IncidentID: "i", ID: "e", Version: 1, Kind: incident.Evidence, Body: json.RawMessage(`{"code":"HEALTHY"}`), ObservedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute)}
	item.Seal()
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.PutItem(item)
	}); err != nil {
		t.Fatal(err)
	}
	s := Service{DB: db, Policy: policy}
	r := AdjudicateRequest{Item: incident.ItemRef{ID: "e", Version: 1}, ItemHash: item.Hash, Reason: "FACTUAL_ERROR", IdempotencyKey: "Alice_customer_secret"}
	a, err := s.Adjudicate(ctx, p, scope, r)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(a)
	if strings.Contains(string(raw), "Alice") {
		t.Fatal("request key leaked")
	}
	again, err := s.Adjudicate(ctx, p, scope, r)
	if err != nil || again.ID != a.ID {
		t.Fatal("retry duplicated")
	}
	r.IdempotencyKey = "confirmed"
	r.Reason = "CONFIRMED"
	if _, err := s.Adjudicate(ctx, p, scope, r); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		ok, err := tx.Uncontested(r.Item)
		if ok {
			t.Fatal("confirmation silently cleared dispute")
		}
		history, e := tx.Adjudications(r.Item, 10)
		if e != nil {
			return e
		}
		if len(history) != 2 {
			t.Fatal("history overwritten")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	other := scope
	other.ClusterID = "other"
	if _, err := s.Adjudicate(ctx, p, other, r); err == nil {
		t.Fatal("cross-scope adjudication")
	}
	if _, err := s.Corroborate(ctx, p, scope, CorroborateRequest{Claim: r.Item, ClaimHash: item.Hash}); err == nil {
		t.Fatal("unchecked causal promotion")
	}
}

func TestCorroborationChecksEligibleContradictionsAndPreservesParents(t *testing.T) {
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
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "stewards", Role: authorization.Steward}})
	p := identity.Principal{ID: "steward", Issuer: "https://idp", Groups: []string{"stewards"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	at := time.Now().Add(-time.Second)
	handle := strings.Repeat("a", 32)
	refs := []incident.ItemRef{{ID: "cause", Version: 1}, {ID: "symptom", Version: 1}}
	var claim incident.Item
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: at}); err != nil {
			return err
		}
		for n, code := range []privacy.Code{privacy.ResourcePressure, privacy.CrashLoop, privacy.Healthy} {
			id := []string{"cause", "symptom", "contradiction"}[n]
			o := privacy.Observation{Code: code, ResourceHandle: handle, ObservedAt: at, ValidUntil: at.Add(time.Minute)}
			raw, _ := json.Marshal(o)
			if err := tx.PutItem(incident.Item{Scope: scope, IncidentID: "i", ID: id, Version: 1, Kind: incident.Evidence, Body: raw, ObservedAt: at, ValidUntil: o.ValidUntil}); err != nil {
				return err
			}
		}
		raw, _ := json.Marshal(investigation.RunResult{RunID: "r", Assessment: investigation.Assessment{Status: investigation.Hypothesis, Conclusion: investigation.Conclusion{CauseCode: privacy.ResourcePressure, ResourceHandle: handle, SupportingEvidence: refs}}})
		claim = incident.Item{Scope: scope, IncidentID: "i", ID: "claim", Version: 1, Kind: incident.Claim, Body: raw, ObservedAt: at, ValidUntil: at.Add(time.Minute), Parents: refs}
		claim.Seal()
		if err := tx.PutItem(claim); err != nil {
			return err
		}
		if err := tx.StartRun("r", "i", "profile", "v1", "prompt", "rubric", at); err != nil {
			return err
		}
		return tx.FinishRun("r", "HYPOTHESIS", "", &incident.ItemRef{ID: claim.ID, Version: 1})
	}); err != nil {
		t.Fatal(err)
	}
	s := Service{DB: db, Policy: policy}
	request := CorroborateRequest{Claim: incident.ItemRef{ID: claim.ID, Version: 1}, ClaimHash: claim.Hash, Evidence: refs, UpstreamChecked: true, TemporalOrderChecked: true, AlternativesTested: true}
	if _, err := s.Corroborate(ctx, p, scope, request); err == nil {
		t.Fatal("omitted current contradiction accepted")
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.Quarantine(incident.ItemRef{ID: "contradiction", Version: 1}) }); err != nil {
		t.Fatal(err)
	}
	corroborated, err := s.Corroborate(ctx, p, scope, request)
	if err != nil {
		t.Fatal("disputed contradictory observation polluted new review", err)
	}
	if len(corroborated.Parents) != 3 {
		t.Fatal("original causal lineage missing")
	}

	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		runs, err := tx.QualityRuns(at.Add(-time.Hour))
		if err != nil {
			return err
		}
		if len(runs) != 1 || len(runs[0].Reviews) != 1 || runs[0].Invalidated {
			t.Fatal("corroboration not counted as independent review", runs)
		}
		if err := tx.Quarantine(refs[0]); err != nil {
			return err
		}
		runs, err = tx.QualityRuns(at.Add(-time.Hour))
		if err == nil && !runs[0].Invalidated {
			t.Fatal("later source dispute left success eligible")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
