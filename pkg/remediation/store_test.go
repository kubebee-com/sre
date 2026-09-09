package remediation

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

func TestFileProposalStoreRoundTripsSanitizedStateAndAudit(t *testing.T) {
	secret := "durable-store-secret-value"
	sanitizer.ConfigureDefaultRedactor(secret)
	t.Cleanup(func() { sanitizer.ConfigureDefaultRedactor() })

	dir := t.TempDir()
	store, err := NewFileProposalStore(dir)
	if err != nil {
		t.Fatalf("NewFileProposalStore() error = %v", err)
	}
	proposal := &Proposal{
		ID:        "proposal-durable-1",
		IssueID:   "issue-durable-1",
		CreatedBy: "scanner",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "payments",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Status:    StatusPending,
		Diagnosis: &triage.Diagnosis{
			IssueID:         "issue-durable-1",
			Summary:         "summary " + secret,
			RootCause:       "root cause",
			Severity:        scanner.SeverityHigh,
			RemediationPlan: "plan",
			ActionType:      triage.ActionManual,
			ProposedCommand: "kubectl get pods -n default",
			ConfidenceScore: 0.7,
		},
		ExecutionError: "execution failed " + secret,
	}
	if err := store.Create(proposal); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	statePath := filepath.Join(dir, "proposals.json")
	encoded, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("proposal state persisted configured secret: %s", encoded)
	}
	if mode := fileMode(t, statePath); mode.Perm() != 0o600 {
		t.Fatalf("proposal state mode = %o, want 600", mode.Perm())
	}
	if entries, err := os.ReadDir(dir); err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	} else if len(entries) != 1 || entries[0].Name() != "proposals.json" {
		t.Fatalf("unexpected files after atomic write: %#v", entries)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileProposalStore(dir)
	if err != nil {
		t.Fatalf("reopen store error = %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	loaded, err := reopened.Get(proposal.ID)
	if err != nil {
		t.Fatalf("reopened Get() error = %v", err)
	}
	if loaded.Diagnosis == nil || strings.Contains(loaded.Diagnosis.Summary, secret) || strings.Contains(loaded.ExecutionError, secret) {
		t.Fatalf("reopened proposal contains unsanitized state: %#v", loaded)
	}
	events, err := reopened.AuditEvents(proposal.ID)
	if err != nil {
		t.Fatalf("AuditEvents() error = %v", err)
	}
	if len(events) != 1 || events[0].Type != AuditEventCreate {
		t.Fatalf("audit events = %#v, want one create event", events)
	}
}

func TestFileProposalStoreFailsClosedForCorruptOrIncompatibleState(t *testing.T) {
	for name, contents := range map[string]string{
		"invalid json":  "{",
		"wrong schema":  `{"schema":"other","version":1,"proposals":[],"audit":[]}`,
		"wrong version": `{"schema":"kubebee.sre/proposals","version":99,"proposals":[],"audit":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "proposals.json")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}
			if _, err := NewFileProposalStore(dir); err == nil {
				t.Fatal("NewFileProposalStore() accepted invalid state")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("invalid state was removed after open failure: %v", err)
			}
		})
	}
}

func TestProposalStoresCloneValuesAndEnforceAtomicMonotonicTransitions(t *testing.T) {
	store := NewMemoryProposalStore()
	proposal := testStoreProposal("proposal-memory-1", "issue-memory-1")
	if err := store.Create(proposal); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	proposal.Diagnosis.Summary = "mutated caller value"
	loaded, err := store.Get(proposal.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if loaded.Diagnosis.Summary == proposal.Diagnosis.Summary {
		t.Fatal("store retained caller's diagnosis pointer")
	}
	loaded.Diagnosis.Summary = "mutated returned value"
	unchanged, err := store.Get(proposal.ID)
	if err != nil {
		t.Fatalf("second Get() error = %v", err)
	}
	if unchanged.Diagnosis.Summary == loaded.Diagnosis.Summary {
		t.Fatal("Get() returned a live diagnosis pointer")
	}

	if _, err := store.Transition(proposal.ID, StatusPending, StatusApproved, nil, AuditEvent{Type: AuditEventApprove, Actor: "alice"}); err != nil {
		t.Fatalf("pending to approved transition error = %v", err)
	}
	if _, err := store.Transition(proposal.ID, StatusPending, StatusRejected, nil, AuditEvent{Type: AuditEventReject, Actor: "bob"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("second transition error = %v, want ErrInvalidTransition", err)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	return info.Mode()
}

func testStoreProposal(id, issueID string) *Proposal {
	now := time.Now().UTC()
	return &Proposal{
		ID:        id,
		IssueID:   issueID,
		CreatedBy: "test",
		CreatedAt: now,
		UpdatedAt: now,
		Namespace: "default",
		Kind:      "Pod",
		Name:      id,
		Status:    StatusPending,
		Diagnosis: &triage.Diagnosis{
			IssueID:         issueID,
			Summary:         "summary",
			RootCause:       "root",
			Severity:        scanner.SeverityMedium,
			RemediationPlan: "plan",
			ActionType:      triage.ActionManual,
			ProposedCommand: "kubectl get pods -n default",
			ConfidenceScore: 0.5,
		},
	}
}
