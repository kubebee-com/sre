package remediation

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEngineRecoversApprovedWorkAfterStoreReopen(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileProposalStore(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("NewFileProposalStore() error = %v", err)
	}
	proposal := testStoreProposal("proposal-recovery", "issue-recovery")
	if err := store.Create(proposal); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if _, err := store.Transition(proposal.ID, StatusPending, StatusApproved, nil, AuditEvent{Type: AuditEventApprove, Actor: "operator"}); err != nil {
		t.Fatalf("approve transition error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reopened, err := NewFileProposalStore(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatalf("reopen store error = %v", err)
	}
	engine := NewEngineWithOptions(fake.NewSimpleClientset(), EngineOptions{
		Store:            reopened,
		Executor:         recoveryTestExecutor{},
		ExecutionTimeout: time.Second,
	})
	defer engine.Close()
	waitForStatus(t, engine, proposal.ID, StatusCompleted)
}

func TestEngineConcurrentApprovalsCommitOnlyOneTransition(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	engine := NewEngineWithOptions(fake.NewSimpleClientset(), EngineOptions{
		Executor:         blockingTestExecutor{started: started, release: release},
		ExecutionTimeout: time.Second,
	})
	defer engine.Close()
	issue := &scanner.Issue{ID: "issue-concurrent-approval", Kind: "Pod", Name: "payments"}
	proposal := engine.CreateProposal(issue, testStoreProposalDiagnosis(issue.ID))
	if proposal == nil {
		t.Fatal("CreateProposal() returned nil")
	}
	results := make(chan error, 2)
	for _, actor := range []string{"alice", "bob"} {
		go func(actor string) {
			_, err := engine.Approve(context.Background(), proposal.ID, actor)
			results <- err
		}(actor)
	}
	var successes int
	for range 2 {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent approval successes = %d, want 1", successes)
	}
	<-started
	close(release)
	waitForStatus(t, engine, proposal.ID, StatusCompleted)
}

func TestEngineBoundsExecutionContext(t *testing.T) {
	engine := NewEngineWithOptions(fake.NewSimpleClientset(), EngineOptions{
		Executor:         contextWaitingExecutor{},
		ExecutionTimeout: 10 * time.Millisecond,
	})
	defer engine.Close()
	issue := &scanner.Issue{ID: "issue-timeout", Kind: "Pod", Name: "payments"}
	proposal := engine.CreateProposal(issue, testStoreProposalDiagnosis(issue.ID))
	if proposal == nil {
		t.Fatal("CreateProposal() returned nil")
	}
	if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	waitForStatus(t, engine, proposal.ID, StatusFailed)
}

func TestEngineRequiresActorsAndRecordsApprovalRejectionAndExecution(t *testing.T) {
	store := NewMemoryProposalStore()
	engine := NewEngineWithStore(fake.NewSimpleClientset(), store)
	defer engine.Close()

	issue := &scanner.Issue{ID: "issue-audit-1", Namespace: "default", Kind: "Pod", Name: "payments"}
	proposal := engine.CreateProposal(issue, testStoreProposalDiagnosis(issue.ID))
	if proposal == nil {
		t.Fatal("CreateProposal() returned nil")
	}
	if _, err := engine.Approve(context.Background(), proposal.ID, " "); !errors.Is(err, ErrActorRequired) {
		t.Fatalf("blank approval actor error = %v, want ErrActorRequired", err)
	}
	if _, err := engine.Reject(proposal.ID, "\t"); !errors.Is(err, ErrActorRequired) {
		t.Fatalf("blank rejection actor error = %v, want ErrActorRequired", err)
	}

	if _, err := engine.Reject(proposal.ID, "reviewer", "false alarm"); err != nil {
		t.Fatalf("Reject() error = %v", err)
	}
	proposal2 := engine.CreateProposal(&scanner.Issue{ID: "issue-audit-2", Namespace: "default", Kind: "Pod", Name: "payments-2"}, testStoreProposalDiagnosis("issue-audit-2"))
	if _, err := engine.Approve(context.Background(), proposal2.ID, "approver"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	waitForStatus(t, engine, proposal2.ID, StatusCompleted)

	events, err := engine.ListAuditEvents("")
	if err != nil {
		t.Fatalf("ListAuditEvents() error = %v", err)
	}
	seen := map[AuditEventType]bool{}
	for _, event := range events {
		seen[event.Type] = true
	}
	for _, eventType := range []AuditEventType{AuditEventCreate, AuditEventApprove, AuditEventReject, AuditEventExecution} {
		if !seen[eventType] {
			t.Errorf("audit events omitted %q: %#v", eventType, events)
		}
	}
}

func TestEngineAuditsPolicyRejectedApproval(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "system-pod", Namespace: "kube-system", UID: types.UID("system-uid"), ResourceVersion: "3",
	}, Status: corev1.PodStatus{Phase: corev1.PodFailed}})
	engine := NewEngine(client)
	defer engine.Close()
	issue := &scanner.Issue{
		ID:                    "issue-protected-approval",
		Namespace:             "kube-system",
		Kind:                  "Pod",
		Name:                  "system-pod",
		TargetUID:             "system-uid",
		TargetResourceVersion: "3",
		Severity:              scanner.SeverityHigh,
	}
	diagnosis := &triage.Diagnosis{
		IssueID:         issue.ID,
		Summary:         "protected pod",
		RootCause:       "policy",
		Severity:        scanner.SeverityHigh,
		RemediationPlan: "delete only after approval",
		ActionType:      triage.ActionDeleteFailedPod,
		ProposedCommand: "kubectl delete pod system-pod -n kube-system",
		ConfidenceScore: 1,
	}
	proposal := engine.CreateProposal(issue, diagnosis)
	if proposal == nil {
		t.Fatal("CreateProposal() returned nil")
	}
	rejected, err := engine.Approve(context.Background(), proposal.ID, "operator")
	if !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("Approve() error = %v, want ErrProtectedTarget", err)
	}
	if rejected == nil || rejected.Status != StatusRejected {
		t.Fatalf("policy-rejected proposal = %#v, want status %s", rejected, StatusRejected)
	}
	events, err := engine.ListAuditEvents(proposal.ID)
	if err != nil {
		t.Fatalf("ListAuditEvents() error = %v", err)
	}
	if len(events) < 2 || events[len(events)-1].Type != AuditEventReject {
		t.Fatalf("policy rejection audit events = %#v, want final reject event", events)
	}
}

func TestEngineDeduplicatesExecutingProposalsAndReturnsDeepCopies(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	store := NewMemoryProposalStore()
	engine := NewEngineWithOptions(fake.NewSimpleClientset(), EngineOptions{
		Store:            store,
		Executor:         blockingTestExecutor{started: started, release: release},
		WorkerCount:      1,
		QueueSize:        1,
		ExecutionTimeout: time.Second,
	})
	defer engine.Close()

	issue := &scanner.Issue{ID: "issue-dedup-1", Namespace: "default", Kind: "Pod", Name: "payments"}
	proposal := engine.CreateProposal(issue, testStoreProposalDiagnosis(issue.ID))
	if proposal == nil {
		t.Fatal("CreateProposal() returned nil")
	}
	proposal.Diagnosis.Summary = "caller mutation"
	proposal.Status = StatusRejected
	stored, ok := engine.GetProposal(proposal.ID)
	if !ok || stored.Status != StatusPending || stored.Diagnosis.Summary == "caller mutation" {
		t.Fatalf("GetProposal() did not return an isolated copy: %#v, %v", stored, ok)
	}

	if _, err := engine.Approve(context.Background(), proposal.ID, "approver"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	<-started
	duplicate := engine.CreateProposal(issue, testStoreProposalDiagnosis(issue.ID))
	if duplicate == nil || duplicate.ID != proposal.ID {
		t.Fatalf("active duplicate = %#v, want proposal %q", duplicate, proposal.ID)
	}
	duplicate.Status = StatusRejected
	current, _ := engine.GetProposal(proposal.ID)
	if current.Status != StatusExecuting {
		t.Fatalf("mutating duplicate changed stored status to %s", current.Status)
	}
	close(release)
	waitForStatus(t, engine, proposal.ID, StatusCompleted)
}

func TestEngineGeneratesDistinctProposalIDs(t *testing.T) {
	engine := NewEngine(fake.NewSimpleClientset())
	defer engine.Close()
	first := engine.CreateProposal(&scanner.Issue{ID: "issue-id-1", Kind: "Pod", Name: "one"}, testStoreProposalDiagnosis("issue-id-1"))
	second := engine.CreateProposal(&scanner.Issue{ID: "issue-id-2", Kind: "Pod", Name: "two"}, testStoreProposalDiagnosis("issue-id-2"))
	if first == nil || second == nil || first.ID == second.ID {
		t.Fatalf("proposal IDs = %q and %q, want distinct IDs", first.ID, second.ID)
	}
}

func testStoreProposalDiagnosis(issueID string) *triage.Diagnosis {
	return &triage.Diagnosis{
		IssueID:         issueID,
		Summary:         "summary",
		RootCause:       "root",
		Severity:        scanner.SeverityMedium,
		RemediationPlan: "plan",
		ActionType:      triage.ActionManual,
		ProposedCommand: "kubectl get pods -n default",
		ConfidenceScore: 0.5,
	}
}

func waitForStatus(t *testing.T, engine *Engine, id string, want ProposalStatus) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		proposal, ok := engine.GetProposal(id)
		if ok && proposal.Status == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	proposal, _ := engine.GetProposal(id)
	t.Fatalf("proposal status = %s, want %s", proposal.Status, want)
}

type blockingTestExecutor struct {
	started chan struct{}
	release chan struct{}
}

func (e blockingTestExecutor) Execute(_ context.Context, _ *Proposal) (string, error) {
	close(e.started)
	<-e.release
	return "completed", nil
}

type recoveryTestExecutor struct{}

func (recoveryTestExecutor) Execute(context.Context, *Proposal) (string, error) {
	return "recovered", nil
}

type contextWaitingExecutor struct{}

func (contextWaitingExecutor) Execute(ctx context.Context, _ *Proposal) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func TestAuditErrorsDoNotExposeRawSecrets(t *testing.T) {
	secret := "audit-error-secret"
	store := NewMemoryProposalStore()
	proposal := testStoreProposal("proposal-audit-secret", "issue-audit-secret")
	proposal.ExecutionError = "password=" + secret
	if err := store.Create(proposal); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	events, err := store.AuditEvents(proposal.ID)
	if err != nil {
		t.Fatalf("AuditEvents() error = %v", err)
	}
	if strings.Contains(string(events[0].Type), secret) {
		t.Fatal("audit event unexpectedly retained secret")
	}
}
