package remediation

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kubebee-com/sre/pkg/triage"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestExecutorDoesNotRetryAFailedPodDeleteWithForce(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "payments", Namespace: "default", UID: types.UID("pod-uid-1"), ResourceVersion: "7",
	}})
	deleteCalls := 0
	client.PrependReactor("delete", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteCalls++
		return true, nil, fmt.Errorf("simulated API failure")
	})

	proposal := &Proposal{
		ID:                    "proposal-delete-failure",
		Namespace:             "default",
		Kind:                  "Pod",
		Name:                  "payments",
		TargetUID:             "pod-uid-1",
		TargetResourceVersion: "7",
		Diagnosis:             &triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod},
	}
	_, err := NewExecutor(client).Execute(context.Background(), proposal)
	if err == nil {
		t.Fatal("Execute() acknowledged failed pod deletion")
	}
	if deleteCalls != 1 {
		t.Fatalf("pod delete calls = %d, want exactly one", deleteCalls)
	}
}

func TestExecutorRejectsUnsupportedActions(t *testing.T) {
	proposal := &Proposal{
		ID:        "proposal-unsupported",
		Namespace: "default",
		Kind:      "Deployment",
		Name:      "payments",
		Diagnosis: &triage.Diagnosis{ActionType: triage.ActionScaleWorkload},
	}
	_, err := NewExecutor(fake.NewSimpleClientset()).Execute(context.Background(), proposal)
	if err == nil {
		t.Fatal("Execute() acknowledged unsupported action")
	}
}

func TestExecutorUsesCapturedPodUIDAndResourceVersionPreconditions(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "payments", Namespace: "default", UID: types.UID("pod-uid-1"), ResourceVersion: "7",
	}})
	var deleteOptions metav1.DeleteOptions
	client.PrependReactor("delete", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		deleteOptions = action.(k8stesting.DeleteAction).GetDeleteOptions()
		return false, nil, nil
	})
	proposal := &Proposal{
		ID:                    "proposal-precondition",
		Namespace:             "default",
		Kind:                  "Pod",
		Name:                  "payments",
		TargetUID:             "pod-uid-1",
		TargetResourceVersion: "7",
		Diagnosis:             &triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod},
	}
	if _, err := NewExecutor(client).Execute(context.Background(), proposal); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if deleteOptions.Preconditions == nil || deleteOptions.Preconditions.UID == nil || string(*deleteOptions.Preconditions.UID) != proposal.TargetUID || deleteOptions.Preconditions.ResourceVersion == nil || *deleteOptions.Preconditions.ResourceVersion != proposal.TargetResourceVersion {
		t.Fatalf("delete preconditions = %#v, want UID/resourceVersion", deleteOptions.Preconditions)
	}
}

func TestExecutorRejectsStaleCapturedPodIdentity(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "payments", Namespace: "default", UID: types.UID("new-uid"), ResourceVersion: "8",
	}})
	proposal := &Proposal{
		ID:                    "proposal-stale",
		Namespace:             "default",
		Kind:                  "Pod",
		Name:                  "payments",
		TargetUID:             "old-uid",
		TargetResourceVersion: "7",
		Diagnosis:             &triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod},
	}
	_, err := NewExecutor(client).Execute(context.Background(), proposal)
	if !errors.Is(err, ErrStalePrecondition) {
		t.Fatalf("stale Execute() error = %v, want ErrStalePrecondition", err)
	}
}

func TestExecutorRequiresBothMutationPreconditions(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "payments", Namespace: "default", UID: types.UID("pod-uid-1"), ResourceVersion: "7",
	}})
	proposal := &Proposal{
		Namespace: "default", Kind: "Pod", Name: "payments", TargetUID: "pod-uid-1",
		Diagnosis: &triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod},
	}
	if err := NewExecutor(client).Validate(context.Background(), proposal); !errors.Is(err, ErrMissingPrecondition) {
		t.Fatalf("Validate() error = %v, want ErrMissingPrecondition", err)
	}
}

func TestExecutorRejectsProtectedAndForceDeletionTargets(t *testing.T) {
	protected := fake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "system-pod", Namespace: "kube-system", UID: types.UID("system-uid"), ResourceVersion: "3",
	}, Status: corev1.PodStatus{Phase: corev1.PodFailed}})
	protectedProposal := &Proposal{
		Namespace: "kube-system", Kind: "Pod", Name: "system-pod", TargetUID: "system-uid", TargetResourceVersion: "3",
		Diagnosis: &triage.Diagnosis{ActionType: triage.ActionDeleteFailedPod},
	}
	if err := NewExecutor(protected).Validate(context.Background(), protectedProposal); !errors.Is(err, ErrProtectedTarget) {
		t.Fatalf("protected Validate() error = %v, want ErrProtectedTarget", err)
	}

	forceProposal := &Proposal{Namespace: "default", Kind: "Pod", Name: "payments", Diagnosis: &triage.Diagnosis{
		ActionType: triage.ActionDeleteFailedPod, ProposedCommand: "kubectl delete pod payments --grace-period=0 --force",
	}}
	if err := NewExecutor(fake.NewSimpleClientset()).Validate(context.Background(), forceProposal); !errors.Is(err, ErrForceDeletion) {
		t.Fatalf("force Validate() error = %v, want ErrForceDeletion", err)
	}
}
