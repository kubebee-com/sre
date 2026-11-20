package legacyserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/agentharness"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	"k8s.io/client-go/kubernetes/fake"
)

type stubAgentRunner struct {
	mu          sync.Mutex
	cfg         agentharness.Config
	planCalls   []agentharness.HarnessKind
	applyCalls  []agentharness.ApplyRequest
	applyResult string
}

func (s *stubAgentRunner) Config() agentharness.Config {
	return s.cfg.Normalized()
}

func (s *stubAgentRunner) CreateSolution(ctx context.Context, issue *scanner.Issue, requested agentharness.HarnessKind) (*agentharness.Solution, error) {
	h, err := s.cfg.ResolveHarness(string(requested))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.planCalls = append(s.planCalls, h)
	s.mu.Unlock()
	return &agentharness.Solution{
		Harness:          h,
		SandboxRuntime:   s.cfg.RuntimeClassName,
		Summary:          "Fix Tempo port 9095 mismatch via " + string(h),
		RootCause:        "Deployment omits containerPort 9095",
		RemediationPlan:  "1. Patch Deployment ports\n2. Verify EndpointSlice",
		ActionType:       triage.ActionAgentRemediation,
		ProposedCommands: []string{"kubectl -n tracing patch deploy tracing-distributor"},
		GitOpsPatch:      "apps/tracing/fluxcd.yaml: +containerPort: 9095",
		VerificationPlan: "Verify endpoints and rerun scan",
		RollbackPlan:     "git revert HEAD",
		ConfidenceScore:  0.94,
		JobName:          "sre-solver-plan-" + string(h) + "-test",
	}, nil
}

func (s *stubAgentRunner) ApplySolution(ctx context.Context, req agentharness.ApplyRequest) (string, error) {
	s.mu.Lock()
	s.applyCalls = append(s.applyCalls, req)
	s.mu.Unlock()
	if s.applyResult != "" {
		return s.applyResult, nil
	}
	return "Applied approved solution via " + string(req.Harness), nil
}

func TestAgentSolverSolveApproveAndRejectFlow(t *testing.T) {
	runner := &stubAgentRunner{
		cfg: agentharness.Config{
			Enabled:          true,
			DefaultHarness:   agentharness.HarnessCodex,
			SandboxMode:      agentharness.SandboxModeK8sJob,
			RuntimeClassName: "gvisor",
		},
	}

	k8sClient := fake.NewSimpleClientset()
	executor := remediation.NewExecutorWithAgent(k8sClient, runner)
	engine := remediation.NewEngineWithOptions(k8sClient, remediation.EngineOptions{
		Store:    remediation.NewMemoryProposalStore(),
		Executor: executor,
	})
	defer func() { _ = engine.Close() }()

	srv := NewServer(0, nil, nil, engine, nil, ServerOptions{
		APIToken:        "test-token-123",
		RequireAPIToken: true,
		AgentSolver:     runner,
	})

	issue := &scanner.Issue{
		ID:        "issue-tracing-9095",
		Namespace: "tracing",
		Kind:      "Service",
		Name:      "tracing-distributor",
		Category:  scanner.CategoryServicePortMismatch,
		Severity:  scanner.SeverityHigh,
		Summary:   "Service tracing-distributor target port 9095 is not declared",
	}
	srv.SetActiveIssues([]*scanner.Issue{issue})

	handler, err := srv.newHandler()
	if err != nil {
		t.Fatalf("newHandler() error = %v", err)
	}

	// 1. Solve with default harness (codex) -> creates PENDING_APPROVAL proposal.
	req := httptest.NewRequest(http.MethodPost, "/api/issues/issue-tracing-9095/solve", nil)
	req.Header.Set("Authorization", "Bearer test-token-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /solve (default codex) status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var prop1 remediation.SanitizedProposal
	if err := json.Unmarshal(rec.Body.Bytes(), &prop1); err != nil {
		t.Fatalf("decode proposal: %v", err)
	}
	if prop1.Status != remediation.StatusPending {
		t.Fatalf("proposal status = %q, want PENDING_APPROVAL", prop1.Status)
	}
	if prop1.Diagnosis == nil || prop1.Diagnosis.AgentHarness != "codex" || prop1.Diagnosis.SandboxRuntime != "gvisor" {
		t.Fatalf("unexpected diagnosis metadata: %+v", prop1.Diagnosis)
	}

	// 2. Approve proposal -> triggers ApplySolution with codex.
	approveReq := httptest.NewRequest(http.MethodPost, "/api/proposals/"+prop1.ID+"/approve", nil)
	approveReq.Header.Set("Authorization", "Bearer test-token-123")
	approveRec := httptest.NewRecorder()
	handler.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("POST /approve status = %d, body = %s", approveRec.Code, approveRec.Body.String())
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runner.mu.Lock()
		n := len(runner.applyCalls)
		runner.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	runner.mu.Lock()
	if len(runner.applyCalls) != 1 || runner.applyCalls[0].Harness != agentharness.HarnessCodex {
		t.Fatalf("expected 1 codex apply call, got %+v", runner.applyCalls)
	}
	runner.mu.Unlock()

	// 3. Solve with explicit `agy` harness and reject -> must NOT execute apply.
	agyBody := bytes.NewBufferString(`{"harness":"agy"}`)
	agyReq := httptest.NewRequest(http.MethodPost, "/api/issues/issue-tracing-9095/solve", agyBody)
	agyReq.Header.Set("Authorization", "Bearer test-token-123")
	agyReq.Header.Set("Content-Type", "application/json")
	agyRec := httptest.NewRecorder()
	handler.ServeHTTP(agyRec, agyReq)
	if agyRec.Code != http.StatusCreated {
		t.Fatalf("POST /solve (agy) status = %d, body = %s", agyRec.Code, agyRec.Body.String())
	}
	var prop2 remediation.SanitizedProposal
	if err := json.Unmarshal(agyRec.Body.Bytes(), &prop2); err != nil {
		t.Fatalf("decode agy proposal: %v", err)
	}
	if prop2.Diagnosis == nil || prop2.Diagnosis.AgentHarness != "agy" {
		t.Fatalf("expected agy harness in proposal, got %+v", prop2.Diagnosis)
	}

	rejectReq := httptest.NewRequest(http.MethodPost, "/api/proposals/"+prop2.ID+"/reject", strings.NewReader(`{"reason":"manual fix preferred"}`))
	rejectReq.Header.Set("Authorization", "Bearer test-token-123")
	rejectReq.Header.Set("Content-Type", "application/json")
	rejectRec := httptest.NewRecorder()
	handler.ServeHTTP(rejectRec, rejectReq)
	if rejectRec.Code != http.StatusOK {
		t.Fatalf("POST /reject status = %d, body = %s", rejectRec.Code, rejectRec.Body.String())
	}
	time.Sleep(50 * time.Millisecond)
	runner.mu.Lock()
	if len(runner.applyCalls) != 1 {
		t.Fatalf("rejected proposal must not invoke apply; got %d apply calls", len(runner.applyCalls))
	}
	runner.mu.Unlock()
}
