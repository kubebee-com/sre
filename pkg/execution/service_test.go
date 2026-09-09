package execution

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestExactOwnerApprovalAndSingleSubmission(t *testing.T) {
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
	bindings := []authorization.Binding{{Scope: scope, Group: "admins", Role: authorization.Administrator}, {Scope: scope, Group: "owner", Role: authorization.Owner}, {Scope: scope, Group: "investigator", Role: authorization.Investigator}}
	policy, _ := authorization.NewPolicy(bindings)
	principal := func(group string) identity.Principal {
		return identity.Principal{ID: group, Issuer: "https://idp", Groups: []string{group}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute)}
	}
	f, _ := fleet.NewService(db, policy, "authority")
	enroll := func(id, role string) fleet.Credential {
		b, err := f.Bootstrap(ctx, principal("admins"), scope, id, "cluster", role)
		if err != nil {
			t.Fatal(err)
		}
		c, err := f.Enroll(ctx, scope, b.Token, "cluster", role)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	collection := enroll("collector", fleet.Collector)
	executor := enroll("executor", fleet.Executor)
	observation := privacy.Observation{Code: privacy.CrashLoop, ResourceHandle: strings.Repeat("a", 32), Target: &privacy.Target{Kind: "Pod", UID: "11111111-1111-1111-1111-111111111111", ResourceVersion: "7", Commitment: strings.Repeat("b", 64)}, Source: &privacy.Provenance{AgentID: collection.Agent.ID, Generation: collection.Agent.Generation, Epoch: f.Epoch, ReportID: identity.NewID()}, ObservedAt: time.Now().Add(-time.Second), ValidUntil: time.Now().Add(5 * time.Minute)}
	body, _ := json.Marshal(observation)
	item := incident.Item{Scope: scope, IncidentID: "incident", ID: "evidence", Version: 1, Kind: incident.Evidence, Body: body, ObservedAt: observation.ObservedAt, ValidUntil: observation.ValidUntil}
	item.Seal()
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.PutItem(item)
	}); err != nil {
		t.Fatal(err)
	}
	s := Service{Fleet: f, Enabled: true}
	request := ProposeRequest{IncidentID: "incident", Kind: "REPLACE_POD", Evidence: incident.ItemRef{ID: item.ID, Version: 1}, EvidenceHash: item.Hash, ExecutorID: executor.Agent.ID}
	a, err := s.Propose(ctx, principal("investigator"), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, scope, executor.Token, a.Plan.ID); err == nil {
		t.Fatal("unapproved action claimed")
	}
	if _, err := s.Approve(ctx, principal("investigator"), scope, a.Plan.ID, a.Hash); err == nil {
		t.Fatal("investigator self-authorized")
	}
	if _, err := s.Approve(ctx, principal("owner"), scope, a.Plan.ID, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong hash approved")
	}
	if _, err := s.Approve(ctx, principal("owner"), scope, a.Plan.ID, a.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, scope, collection.Token, a.Plan.ID); err == nil {
		t.Fatal("collector claimed mutation")
	}
	var wins atomic.Int32
	var claim Claim
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.Claim(ctx, scope, executor.Token, a.Plan.ID)
			if err == nil {
				wins.Add(1)
				mu.Lock()
				claim = c
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("submission winners %d", wins.Load())
	}
	if _, err := s.Claim(ctx, scope, executor.Token, a.Plan.ID); err == nil {
		t.Fatal("submitted action replayed")
	}
	if _, err := s.Receipt(ctx, scope, executor.Token, a.Plan.ID, "wrong", "APPLIED"); err == nil {
		t.Fatal("forged receipt")
	}
	done, err := s.Receipt(ctx, scope, executor.Token, a.Plan.ID, claim.ReceiptToken, "APPLIED")
	if err != nil || done.State != "APPLIED" {
		t.Fatal("receipt", err)
	}
	if done.OutcomeCode == "RECOVERED" {
		t.Fatal("operation effect became recovery")
	}
	a, err = s.Propose(ctx, principal("investigator"), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(ctx, principal("owner"), scope, a.Plan.ID, a.Hash); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.Quarantine(request.Evidence) }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, scope, executor.Token, a.Plan.ID); err == nil {
		t.Fatal("disputed evidence authorized mutation")
	}
	request.Kind = "EXEC"
	if _, err := s.Propose(ctx, principal("owner"), scope, request); err == nil {
		t.Fatal("unknown write accepted")
	}
}
