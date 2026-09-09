package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestEngineOptionsPreservesLegacyFieldShape(t *testing.T) {
	options := EngineOptions{nil, nil, 0, 0, 0, 0}
	if options.Store != nil || options.Executor != nil || options.WorkerCount != 0 || options.QueueSize != 0 || options.ExecutionTimeout != 0 || options.ProposalTTL != 0 {
		t.Fatalf("legacy EngineOptions positional fields changed: %#v", options)
	}
}

func TestVerificationAndObserverUseConfiguredBoundedContexts(t *testing.T) {
	verificationRemaining := make(chan time.Duration, 1)
	observerRemaining := make(chan time.Duration, 1)
	verifier := verifierFunc(func(ctx context.Context, _ *Proposal) (VerificationResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return VerificationResult{}, errors.New("verification context has no deadline")
		}
		verificationRemaining <- time.Until(deadline)
		return verifiedResult("target converged"), nil
	})
	observer := outcomeObserverFunc(func(ctx context.Context, _ *Proposal) error {
		deadline, ok := ctx.Deadline()
		if !ok {
			return errors.New("observer context has no deadline")
		}
		observerRemaining <- time.Until(deadline)
		return nil
	})
	engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
		Executor: staticExecutor{result: "mutation accepted"},
	}, EngineVerificationOptions{
		Verifier:               verifier,
		OutcomeObserver:        observer,
		VerificationTimeout:    250 * time.Millisecond,
		OutcomeObserverTimeout: 50 * time.Millisecond,
	})
	defer engine.Close()
	proposal := mustCreateVerificationProposal(t, engine,
		&scanner.Issue{ID: "issue-bounded-contexts", Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1", TargetResourceVersion: "7"},
		&triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default"},
	)
	if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	waitForStatus(t, engine, proposal.ID, StatusCompleted)
	assertRemainingWithinTimeout(t, "verification", verificationRemaining, 250*time.Millisecond)
	assertRemainingWithinTimeout(t, "observer", observerRemaining, 50*time.Millisecond)
}

func assertRemainingWithinTimeout(t *testing.T, name string, remaining <-chan time.Duration, timeout time.Duration) {
	t.Helper()
	select {
	case got := <-remaining:
		if got <= 0 || got > timeout {
			t.Fatalf("%s context remaining = %s, want > 0 and <= %s", name, got, timeout)
		}
	case <-time.After(time.Second):
		t.Fatalf("%s did not receive a bounded context", name)
	}
}

func TestVerificationFieldsPersistAcrossJSONAndFileStoreReopen(t *testing.T) {
	secret := "verification-persistence-secret"
	sanitizer.ConfigureDefaultRedactor(secret)
	t.Cleanup(func() { sanitizer.ConfigureDefaultRedactor() })

	verificationError := "verification failed: " + secret + " " + strings.Repeat("x", maxExecutionErrorBytes*2)
	proposal := &Proposal{
		ID:                 "proposal-verification-persistence",
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
		Status:             StatusFailed,
		VerificationStatus: VerificationStatusUnavailable,
		VerificationError:  verificationError,
	}

	for name, value := range map[string]interface{}{
		"proposal": proposal,
		"sanitized proposal": &SanitizedProposal{
			ID:                 proposal.ID,
			Status:             proposal.Status,
			VerificationStatus: proposal.VerificationStatus,
			VerificationError:  verificationError,
		},
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		var decoded struct {
			VerificationStatus VerificationStatus `json:"verification_status"`
			VerificationError  string             `json:"verification_error"`
		}
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("json.Unmarshal(%s) error = %v", name, err)
		}
		assertPersistedVerificationFields(t, name, decoded.VerificationStatus, decoded.VerificationError, secret)
	}

	dir := t.TempDir()
	store, err := NewFileProposalStore(dir)
	if err != nil {
		t.Fatalf("NewFileProposalStore() error = %v", err)
	}
	if err := store.Create(proposal); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
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
	assertPersistedVerificationFields(t, "reopened proposal", loaded.VerificationStatus, loaded.VerificationError, secret)
}

func assertPersistedVerificationFields(t *testing.T, source string, status VerificationStatus, verificationError, secret string) {
	t.Helper()
	if status != VerificationStatusUnavailable {
		t.Fatalf("%s VerificationStatus = %q, want %q", source, status, VerificationStatusUnavailable)
	}
	if verificationError == "" {
		t.Fatalf("%s VerificationError is empty", source)
	}
	if strings.Contains(verificationError, secret) {
		t.Fatalf("%s VerificationError leaked configured secret: %q", source, verificationError)
	}
	if len(verificationError) > maxExecutionErrorBytes {
		t.Fatalf("%s VerificationError length = %d, want <= %d", source, len(verificationError), maxExecutionErrorBytes)
	}
}

func TestVerificationSuccessfulTypedActionsProduceLearningOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		client     kubernetes.Interface
		issue      scanner.Issue
		diagnosis  triage.Diagnosis
		wantResult string
	}{
		{
			name: "delete observes pod gone",
			client: fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
				Name: "payments", Namespace: "default", UID: types.UID("pod-uid-1"), ResourceVersion: "7",
			}, Status: corev1.PodStatus{Phase: corev1.PodFailed}}),
			issue: scanner.Issue{
				ID: "issue-delete", Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1", TargetResourceVersion: "7",
			},
			diagnosis: triage.Diagnosis{
				ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default",
			},
			wantResult: "Successfully deleted pod",
		},
		{
			name: "scale observes requested replica count",
			client: fake.NewSimpleClientset(&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
				Name: "payments", Namespace: "default", UID: types.UID("deploy-uid-1"), ResourceVersion: "11",
			}, Spec: appsv1.DeploymentSpec{Replicas: int32Ptr(1)}}),
			issue: scanner.Issue{
				ID: "issue-scale", Namespace: "default", Kind: "Deployment", Name: "payments", TargetUID: "deploy-uid-1", TargetResourceVersion: "11",
			},
			diagnosis: triage.Diagnosis{
				ActionType: triage.ActionScaleWorkload, ProposedCommand: "kubectl scale deployment/payments --replicas=3 -n default", TargetReplicas: int32Ptr(3),
			},
			wantResult: "Successfully set default/payments replicas to 3",
		},
		{
			name: "cordon observes unschedulable",
			client: fake.NewSimpleClientset(&corev1.Node{ObjectMeta: metav1.ObjectMeta{
				Name: "worker-1", UID: types.UID("node-uid-1"), ResourceVersion: "21",
			}}),
			issue: scanner.Issue{
				ID: "issue-cordon", Kind: "Node", Name: "worker-1", TargetUID: "node-uid-1", TargetResourceVersion: "21",
			},
			diagnosis: triage.Diagnosis{
				ActionType: triage.ActionCordonNode, ProposedCommand: "kubectl cordon worker-1",
			},
			wantResult: "Successfully cordoned node worker-1",
		},
		{
			name:   "rollout observes changed target revision",
			client: rolloutRestartClient(t, true),
			issue: scanner.Issue{
				ID: "issue-rollout", Namespace: "default", Kind: "Deployment", Name: "payments", TargetUID: "deploy-uid-2", TargetResourceVersion: "31",
			},
			diagnosis: triage.Diagnosis{
				ActionType: triage.ActionRolloutRestart, ProposedCommand: "kubectl rollout restart deployment/payments -n default",
			},
			wantResult: "Successfully triggered rollout restart",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observer := &recordingOutcomeObserver{}
			engine := NewEngineWithVerificationOptions(tc.client, EngineOptions{ExecutionTimeout: time.Second}, EngineVerificationOptions{OutcomeObserver: observer})
			defer engine.Close()

			proposal := mustCreateVerificationProposal(t, engine, &tc.issue, &tc.diagnosis)
			if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
				t.Fatalf("Approve() error = %v", err)
			}

			waitForStatus(t, engine, proposal.ID, StatusCompleted)
			waitForOutcomeCount(t, observer, 1)
			completed, _ := engine.GetProposal(proposal.ID)
			if completed.VerificationStatus != VerificationStatusVerified {
				t.Fatalf("VerificationStatus = %q, want %q; error=%q", completed.VerificationStatus, VerificationStatusVerified, completed.VerificationError)
			}
			if completed.VerificationError != "" {
				t.Fatalf("VerificationError = %q, want empty", completed.VerificationError)
			}
			if !strings.Contains(completed.ExecutionResult, tc.wantResult) {
				t.Fatalf("ExecutionResult = %q, want substring %q", completed.ExecutionResult, tc.wantResult)
			}
			if got := observer.proposals()[0]; got.Status != StatusCompleted || got.VerificationStatus != VerificationStatusVerified {
				t.Fatalf("observer saw proposal status=%s verification=%s, want completed verified", got.Status, got.VerificationStatus)
			}
		})
	}
}

func TestVerificationRolloutRequiresChangedDeploymentGeneration(t *testing.T) {
	for _, tc := range []struct {
		name              string
		generationChanged bool
		wantStatus        VerificationStatus
	}{
		{name: "unrelated metadata and resourceVersion change", wantStatus: VerificationStatusFailed},
		{name: "deployment generation change", generationChanged: true, wantStatus: VerificationStatusVerified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor := NewExecutor(rolloutRestartClient(t, tc.generationChanged))
			proposal := &Proposal{
				ID:                    "proposal-rollout-generation",
				Namespace:             "default",
				Kind:                  "Deployment",
				Name:                  "payments",
				TargetUID:             "deploy-uid-2",
				TargetResourceVersion: "31",
				Diagnosis: &triage.Diagnosis{
					ActionType:      triage.ActionRolloutRestart,
					ProposedCommand: "kubectl rollout restart deployment/payments -n default",
				},
			}
			if _, err := executor.Execute(context.Background(), proposal); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			result, err := executor.Verify(context.Background(), proposal)
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if result.Status != tc.wantStatus {
				t.Fatalf("Verify() status = %q, want %q; message=%q", result.Status, tc.wantStatus, result.Message)
			}
		})
	}
}

func TestVerificationPodDeletionPollsUntilOriginalUIDIsGone(t *testing.T) {
	proposal := &Proposal{
		Namespace: "default",
		Name:      "payments",
		TargetUID: "pod-uid-1",
		Diagnosis: &triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod},
	}

	t.Run("delayed deletion", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		getCalls := 0
		client.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			getCalls++
			if getCalls < 3 {
				return true, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(proposal.TargetUID)}}, nil
			}
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, proposal.Name)
		})
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		result, err := NewExecutor(client).Verify(ctx, proposal)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if result.Status != VerificationStatusVerified {
			t.Fatalf("Verify() status = %q, want %q; message=%q", result.Status, VerificationStatusVerified, result.Message)
		}
		if getCalls < 3 {
			t.Fatalf("pod GET calls = %d, want at least 3", getCalls)
		}
	})

	t.Run("UID replacement", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		client.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID("replacement-uid")}}, nil
		})
		result, err := NewExecutor(client).Verify(context.Background(), proposal)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if result.Status != VerificationStatusVerified {
			t.Fatalf("Verify() status = %q, want %q; message=%q", result.Status, VerificationStatusVerified, result.Message)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		getCalls := 0
		client.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			getCalls++
			return true, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(proposal.TargetUID)}}, nil
		})
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		result, err := NewExecutor(client).Verify(ctx, proposal)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if result.Status != VerificationStatusFailed {
			t.Fatalf("Verify() status = %q, want %q; message=%q", result.Status, VerificationStatusFailed, result.Message)
		}
		if getCalls < 2 {
			t.Fatalf("pod GET calls = %d, want polling before timeout", getCalls)
		}
	})
}

func TestVerificationFailedUnavailableAndUnverifiedPathsDoNotProduceLearningOutcomes(t *testing.T) {
	t.Run("action failure", func(t *testing.T) {
		observer := &recordingOutcomeObserver{}
		engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
			Executor:         staticExecutor{err: errors.New("api rejected mutation")},
			ExecutionTimeout: time.Second,
		}, EngineVerificationOptions{OutcomeObserver: observer})
		defer engine.Close()
		proposal := mustCreateVerificationProposal(t, engine,
			&scanner.Issue{ID: "issue-execute-fail", Kind: "Pod", Name: "payments"},
			&triage.Diagnosis{ActionType: triage.ActionManual, ProposedCommand: "kubectl get pods -n default"},
		)
		if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
			t.Fatalf("Approve() error = %v", err)
		}
		waitForStatus(t, engine, proposal.ID, StatusFailed)
		waitForOutcomeCount(t, observer, 0)
	})

	t.Run("stale target", func(t *testing.T) {
		observer := &recordingOutcomeObserver{}
		client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "payments", Namespace: "default", UID: types.UID("new-uid"), ResourceVersion: "8",
		}})
		engine := NewEngineWithVerificationOptions(client, EngineOptions{ExecutionTimeout: time.Second}, EngineVerificationOptions{OutcomeObserver: observer})
		defer engine.Close()
		proposal := mustCreateVerificationProposal(t, engine,
			&scanner.Issue{ID: "issue-stale", Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "old-uid", TargetResourceVersion: "7"},
			&triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default"},
		)
		if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); !errors.Is(err, ErrStalePrecondition) {
			t.Fatalf("Approve() error = %v, want ErrStalePrecondition", err)
		}
		stale, _ := engine.GetProposal(proposal.ID)
		if stale.Status != StatusStale {
			t.Fatalf("Status = %s, want %s", stale.Status, StatusStale)
		}
		waitForOutcomeCount(t, observer, 0)
	})

	t.Run("verifier error", func(t *testing.T) {
		observer := &recordingOutcomeObserver{}
		engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
			Executor:         staticExecutor{result: "executed"},
			ExecutionTimeout: time.Second,
		}, EngineVerificationOptions{
			Verifier:        staticVerifier{err: errors.New("verification client down")},
			OutcomeObserver: observer,
		})
		defer engine.Close()
		proposal := mustCreateVerificationProposal(t, engine,
			&scanner.Issue{ID: "issue-verifier-error", Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1", TargetResourceVersion: "7"},
			&triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default"},
		)
		if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
			t.Fatalf("Approve() error = %v", err)
		}
		waitForStatus(t, engine, proposal.ID, StatusCompleted)
		completed, _ := engine.GetProposal(proposal.ID)
		if completed.VerificationStatus != VerificationStatusUnavailable {
			t.Fatalf("VerificationStatus = %q, want %q", completed.VerificationStatus, VerificationStatusUnavailable)
		}
		if completed.VerificationError == "" {
			t.Fatal("VerificationError is empty, want bounded verifier error")
		}
		waitForOutcomeCount(t, observer, 0)
	})

	t.Run("unavailable verification", func(t *testing.T) {
		observer := &recordingOutcomeObserver{}
		engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
			Executor:         staticExecutor{result: "executed"},
			ExecutionTimeout: time.Second,
		}, EngineVerificationOptions{
			Verifier:        staticVerifier{result: VerificationResult{Status: VerificationStatusUnavailable, Message: "typed verifier unavailable"}},
			OutcomeObserver: observer,
		})
		defer engine.Close()
		proposal := mustCreateVerificationProposal(t, engine,
			&scanner.Issue{ID: "issue-verifier-unavailable", Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1", TargetResourceVersion: "7"},
			&triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default"},
		)
		if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
			t.Fatalf("Approve() error = %v", err)
		}
		waitForStatus(t, engine, proposal.ID, StatusCompleted)
		completed, _ := engine.GetProposal(proposal.ID)
		if completed.VerificationStatus != VerificationStatusUnavailable {
			t.Fatalf("VerificationStatus = %q, want %q", completed.VerificationStatus, VerificationStatusUnavailable)
		}
		waitForOutcomeCount(t, observer, 0)
	})

	t.Run("manual and gitops are explicitly unverified", func(t *testing.T) {
		for _, action := range []triage.ActionType{triage.ActionManual, triage.ActionGitOpsPR} {
			observer := &recordingOutcomeObserver{}
			engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{ExecutionTimeout: time.Second}, EngineVerificationOptions{OutcomeObserver: observer})
			proposal := mustCreateVerificationProposal(t, engine,
				&scanner.Issue{ID: "issue-" + string(action), Kind: "Pod", Name: "payments"},
				&triage.Diagnosis{ActionType: action, ProposedCommand: "kubectl get pods -n default"},
			)
			if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
				t.Fatalf("Approve(%s) error = %v", action, err)
			}
			waitForStatus(t, engine, proposal.ID, StatusCompleted)
			completed, _ := engine.GetProposal(proposal.ID)
			if completed.VerificationStatus != VerificationStatusUnverified {
				t.Fatalf("%s VerificationStatus = %q, want %q", action, completed.VerificationStatus, VerificationStatusUnverified)
			}
			waitForOutcomeCount(t, observer, 0)
			if err := engine.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		}
	})
}

func TestVerificationFailurePreservesSuccessfulExecutionState(t *testing.T) {
	for _, tc := range []struct {
		name       string
		verifier   ProposalVerifier
		wantStatus VerificationStatus
	}{
		{
			name:       "failed outcome",
			verifier:   staticVerifier{result: VerificationResult{Status: VerificationStatusFailed, Message: "target state did not converge"}},
			wantStatus: VerificationStatusFailed,
		},
		{
			name:       "unavailable outcome",
			verifier:   staticVerifier{result: VerificationResult{Status: VerificationStatusUnavailable, Message: "verification API unavailable"}},
			wantStatus: VerificationStatusUnavailable,
		},
		{
			name:       "verifier error",
			verifier:   staticVerifier{err: errors.New("verification transport failed")},
			wantStatus: VerificationStatusUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observer := &recordingOutcomeObserver{}
			engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
				Executor:         staticExecutor{result: "mutation accepted"},
				ExecutionTimeout: time.Second,
			}, EngineVerificationOptions{
				Verifier:        tc.verifier,
				OutcomeObserver: observer,
			})
			proposal := mustCreateVerificationProposal(t, engine,
				&scanner.Issue{ID: "issue-truthful-" + tc.name, Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1", TargetResourceVersion: "7"},
				&triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default"},
			)
			if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
				t.Fatalf("Approve() error = %v", err)
			}
			terminal := waitForTerminalProposal(t, engine, proposal.ID)
			if terminal.Status != StatusCompleted {
				t.Fatalf("proposal status = %s, want %s", terminal.Status, StatusCompleted)
			}
			if terminal.ExecutionResult != "mutation accepted" || terminal.ExecutionError != "" {
				t.Fatalf("execution result=%q error=%q, want successful mutation state", terminal.ExecutionResult, terminal.ExecutionError)
			}
			if terminal.VerificationStatus != tc.wantStatus || terminal.VerificationError == "" {
				t.Fatalf("verification status=%q error=%q, want status=%q with error", terminal.VerificationStatus, terminal.VerificationError, tc.wantStatus)
			}
			if err := engine.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got := len(observer.proposals()); got != 0 {
				t.Fatalf("observer invocation count = %d, want 0", got)
			}
		})
	}
}

func TestVerificationUsesFreshContextAfterExecution(t *testing.T) {
	remaining := make(chan time.Duration, 1)
	executor := executorFunc(func(ctx context.Context, _ *Proposal) (string, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return "", errors.New("execution context has no deadline")
		}
		wait := time.Until(deadline) - 10*time.Millisecond
		if wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return "mutation accepted", nil
	})
	verifier := verifierFunc(func(ctx context.Context, _ *Proposal) (VerificationResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return VerificationResult{}, errors.New("verification context has no deadline")
		}
		remaining <- time.Until(deadline)
		return verifiedResult("target converged"), nil
	})
	engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
		Executor:         executor,
		ExecutionTimeout: 80 * time.Millisecond,
	}, EngineVerificationOptions{Verifier: verifier, VerificationTimeout: 2 * time.Second})
	defer engine.Close()
	proposal := mustCreateVerificationProposal(t, engine,
		&scanner.Issue{ID: "issue-fresh-verification-context", Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1", TargetResourceVersion: "7"},
		&triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default"},
	)
	if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	waitForStatus(t, engine, proposal.ID, StatusCompleted)
	select {
	case got := <-remaining:
		if got < time.Second {
			t.Fatalf("verification context remaining = %s, want a fresh bounded timeout", got)
		}
	case <-time.After(time.Second):
		t.Fatal("verifier did not record its context deadline")
	}
}

func TestOutcomeObserverRejectsVerifiedManualAndGitOpsFromCustomVerifier(t *testing.T) {
	for _, action := range []triage.ActionType{triage.ActionManual, triage.ActionGitOpsPR} {
		t.Run(string(action), func(t *testing.T) {
			observer := &recordingOutcomeObserver{}
			engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
				Executor:         staticExecutor{result: "executed"},
				ExecutionTimeout: time.Second,
			}, EngineVerificationOptions{
				Verifier:        staticVerifier{result: VerificationResult{Status: VerificationStatusVerified}},
				OutcomeObserver: observer,
			})
			proposal := mustCreateVerificationProposal(t, engine,
				&scanner.Issue{ID: "issue-adversarial-" + string(action), Kind: "Pod", Name: "payments"},
				&triage.Diagnosis{ActionType: action, ProposedCommand: "kubectl get pods -n default"},
			)
			if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
				t.Fatalf("Approve() error = %v", err)
			}
			waitForStatus(t, engine, proposal.ID, StatusCompleted)
			completed, ok := engine.GetProposal(proposal.ID)
			if !ok {
				t.Fatal("GetProposal() did not return completed proposal")
			}
			if completed.VerificationStatus != VerificationStatusUnverified {
				t.Fatalf("VerificationStatus = %q, want %q", completed.VerificationStatus, VerificationStatusUnverified)
			}
			if err := engine.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got := len(observer.proposals()); got != 0 {
				t.Fatalf("observer invocation count = %d, want 0", got)
			}
		})
	}
}

func TestOutcomeObserverPanicIsRecoveredAndScheduledOnce(t *testing.T) {
	var calls atomic.Int32
	called := make(chan struct{}, 1)
	observer := outcomeObserverFunc(func(context.Context, *Proposal) error {
		calls.Add(1)
		called <- struct{}{}
		panic("observer panic")
	})
	engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
		Executor:         staticExecutor{result: "mutation accepted"},
		ExecutionTimeout: time.Second,
	}, EngineVerificationOptions{
		Verifier:        staticVerifier{result: verifiedResult("target converged")},
		OutcomeObserver: observer,
	})
	proposal := mustCreateVerificationProposal(t, engine,
		&scanner.Issue{ID: "issue-observer-panic", Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1", TargetResourceVersion: "7"},
		&triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default"},
	)
	if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	waitForStatus(t, engine, proposal.ID, StatusCompleted)
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("observer was not invoked")
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("observer invocation count = %d, want 1", got)
	}
}

func TestOutcomeObserverCannotBlockEngineClose(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	observer := outcomeObserverFunc(func(context.Context, *Proposal) error {
		started <- struct{}{}
		<-release
		return nil
	})
	engine := NewEngineWithVerificationOptions(fake.NewSimpleClientset(), EngineOptions{
		Executor:         staticExecutor{result: "mutation accepted"},
		ExecutionTimeout: time.Second,
	}, EngineVerificationOptions{
		Verifier:               staticVerifier{result: verifiedResult("target converged")},
		OutcomeObserver:        observer,
		OutcomeObserverTimeout: 25 * time.Millisecond,
	})
	proposal := mustCreateVerificationProposal(t, engine,
		&scanner.Issue{ID: "issue-observer-block", Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1", TargetResourceVersion: "7"},
		&triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments -n default"},
	)
	if _, err := engine.Approve(context.Background(), proposal.ID, "operator"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	waitForStatus(t, engine, proposal.ID, StatusCompleted)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("observer was not invoked")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- engine.Close() }()
	var closeErr error
	closeBlocked := false
	select {
	case closeErr = <-closeDone:
	case <-time.After(100 * time.Millisecond):
		closeBlocked = true
	}
	close(release)
	if closeBlocked {
		closeErr = <-closeDone
	}
	if closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
	if closeBlocked {
		t.Fatal("Close() blocked on OutcomeObserver")
	}
}

func mustCreateVerificationProposal(t *testing.T, engine *Engine, issue *scanner.Issue, diagnosis *triage.Diagnosis) *Proposal {
	t.Helper()
	fullDiagnosis := *diagnosis
	fullDiagnosis.IssueID = issue.ID
	fullDiagnosis.Summary = "summary"
	fullDiagnosis.RootCause = "root"
	fullDiagnosis.Severity = scanner.SeverityMedium
	fullDiagnosis.RemediationPlan = "plan"
	fullDiagnosis.ConfidenceScore = 0.7
	fullDiagnosis.ProviderName = "test"
	proposal, err := engine.CreateProposalForActor(issue, &fullDiagnosis, "scanner")
	if err != nil {
		t.Fatalf("CreateProposalForActor() error = %v", err)
	}
	return proposal
}

func rolloutRestartClient(t *testing.T, generationChanged bool) *fake.Clientset {
	t.Helper()
	current := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{
		Name: "payments", Namespace: "default", UID: types.UID("deploy-uid-2"), ResourceVersion: "31", Generation: 9,
	}}
	client := fake.NewSimpleClientset(current.DeepCopy())
	client.PrependReactor("get", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		get := action.(k8stesting.GetAction)
		if get.GetNamespace() == current.Namespace && get.GetName() == current.Name {
			return true, current.DeepCopy(), nil
		}
		return false, nil, nil
	})
	client.PrependReactor("patch", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updated := current.DeepCopy()
		updated.ResourceVersion = "32"
		if generationChanged {
			updated.Generation++
			if updated.Spec.Template.Annotations == nil {
				updated.Spec.Template.Annotations = map[string]string{}
			}
			updated.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().UTC().Format(time.RFC3339)
		} else {
			if updated.Labels == nil {
				updated.Labels = map[string]string{}
			}
			updated.Labels["unrelated"] = "metadata-change"
		}
		current = updated
		return true, current.DeepCopy(), nil
	})
	return client
}

func int32Ptr(value int32) *int32 {
	return &value
}

type staticExecutor struct {
	result string
	err    error
}

type executorFunc func(context.Context, *Proposal) (string, error)

func (f executorFunc) Execute(ctx context.Context, proposal *Proposal) (string, error) {
	return f(ctx, proposal)
}

func (e staticExecutor) Execute(context.Context, *Proposal) (string, error) {
	return e.result, e.err
}

type staticVerifier struct {
	result VerificationResult
	err    error
}

func (v staticVerifier) Verify(context.Context, *Proposal) (VerificationResult, error) {
	return v.result, v.err
}

type verifierFunc func(context.Context, *Proposal) (VerificationResult, error)

func (f verifierFunc) Verify(ctx context.Context, proposal *Proposal) (VerificationResult, error) {
	return f(ctx, proposal)
}

type recordingOutcomeObserver struct {
	mu       sync.Mutex
	observed []*Proposal
}

type outcomeObserverFunc func(context.Context, *Proposal) error

func (f outcomeObserverFunc) ObserveOutcome(ctx context.Context, proposal *Proposal) error {
	return f(ctx, proposal)
}

func (o *recordingOutcomeObserver) ObserveOutcome(_ context.Context, proposal *Proposal) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observed = append(o.observed, cloneProposal(proposal))
	return nil
}

func (o *recordingOutcomeObserver) proposals() []*Proposal {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make([]*Proposal, len(o.observed))
	copy(result, o.observed)
	return result
}

func waitForOutcomeCount(t *testing.T, observer *recordingOutcomeObserver, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := len(observer.proposals()); got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("observed outcome count = %d, want %d", len(observer.proposals()), want)
}

func waitForTerminalProposal(t *testing.T, engine *Engine, proposalID string) *Proposal {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		proposal, ok := engine.GetProposal(proposalID)
		if ok {
			switch proposal.Status {
			case StatusCompleted, StatusFailed, StatusStale, StatusExpired:
				return proposal
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("proposal %s did not reach a terminal state", proposalID)
	return nil
}

func TestOutcomeObserverAdmissionRemainsBoundedAfterTimeout(t *testing.T) {
	started := make(chan struct{}, 100)
	release := make(chan struct{})
	defer close(release)
	engine := NewEngineWithVerificationOptions(nil, EngineOptions{}, EngineVerificationOptions{
		OutcomeObserverTimeout: time.Millisecond,
		OutcomeObserver: outcomeObserverFunc(func(context.Context, *Proposal) error {
			started <- struct{}{}
			<-release
			panic("observer failed after release")
		}),
	})
	defer engine.Close()
	for i := 0; i < 4; i++ {
		engine.scheduleOutcome(&Proposal{})
	}
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("observer did not start")
		}
	}
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 20; i++ {
		engine.scheduleOutcome(&Proposal{})
	}
	select {
	case <-started:
		t.Fatal("observer admission exceeded four blocked callbacks after timeout")
	case <-time.After(30 * time.Millisecond):
	}
	release <- struct{}{}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		engine.scheduleOutcome(&Proposal{})
		select {
		case <-started:
			return
		case <-time.After(time.Millisecond):
		}
	}
	t.Fatal("returned callback did not release admission slot")
}
