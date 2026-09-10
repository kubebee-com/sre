package remediation

import (
	"context"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestExecuteVersionBumpOnDeployment(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "nginx-deploy",
			Namespace:       "default",
			UID:             "deploy-uid-123",
			ResourceVersion: "1",
			Generation:      1,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:1.24.0",
						},
					},
				},
			},
		},
	}

	client := fake.NewSimpleClientset(deploy)
	executor := NewExecutor(client)

	proposal := &Proposal{
		ID:                    "prop-bump-1",
		Namespace:             "default",
		Kind:                  "Deployment",
		Name:                  "nginx-deploy",
		TargetUID:             "deploy-uid-123",
		TargetResourceVersion: "1",
		Status:                StatusApproved,
		Diagnosis: &triage.Diagnosis{
			IssueID:         "nginx-vuln",
			Summary:         "Vulnerability in nginx:1.24.0",
			RootCause:       "CVE-2023-44487 Rapid Reset vulnerability",
			RemediationPlan: "Bump container image to nginx:1.26.2-alpine",
			ActionType:      triage.ActionBumpVersion,
			ProposedCommand: "kubectl set image deployment/nginx-deploy nginx=nginx:1.26.2-alpine -n default",
			TargetImage:     "nginx:1.26.2-alpine",
			Severity:        scanner.SeverityHigh,
		},
	}

	// Validate
	if err := executor.Validate(context.Background(), proposal); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	// Execute
	result, err := executor.Execute(context.Background(), proposal)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if result == "" {
		t.Fatal("Execute returned empty result")
	}

	// Verify the deployment image was updated
	updatedDeploy, err := client.AppsV1().Deployments("default").Get(context.Background(), "nginx-deploy", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get updated deployment failed: %v", err)
	}
	if updatedDeploy.Spec.Template.Spec.Containers[0].Image != "nginx:1.26.2-alpine" {
		t.Fatalf("expected updated image nginx:1.26.2-alpine, got %s", updatedDeploy.Spec.Template.Spec.Containers[0].Image)
	}

	// Verify rollout
	verifyResult, err := executor.Verify(context.Background(), proposal)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if verifyResult.Status != VerificationStatusVerified {
		t.Fatalf("expected VerificationStatusVerified, got %v: %s", verifyResult.Status, verifyResult.Message)
	}
}

func TestEngineExecutesApprovedVersionBump(t *testing.T) {
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "api-server",
			Namespace:       "payments",
			UID:             "api-uid-999",
			ResourceVersion: "2",
			Generation:      1,
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "api",
							Image: "redis:6.2.6",
						},
					},
				},
			},
		},
	}

	client := fake.NewSimpleClientset(deploy)
	store := NewMemoryProposalStore()
	executor := NewExecutor(client)
	engine := NewEngineWithOptions(client, EngineOptions{
		Store:            store,
		Executor:         executor,
		ExecutionTimeout: 5 * time.Second,
	})
	defer engine.Close()

	issue := &scanner.Issue{
		ID:                    "issue-redis-cve",
		Namespace:             "payments",
		Kind:                  "Deployment",
		Name:                  "api-server",
		TargetUID:             "api-uid-999",
		TargetResourceVersion: "2",
		Severity:              scanner.SeverityHigh,
		Category:              scanner.CategoryPodVulnerability,
		Summary:               "Outdated redis vulnerable to CVE-2024-31449",
	}

	diagnosis := &triage.Diagnosis{
		IssueID:         issue.ID,
		Summary:         issue.Summary,
		RootCause:       "Outdated redis 6.2.6 has CVE-2024-31449 Lua overflow",
		RemediationPlan: "Upgrade redis to patched 7.2.5-alpine release",
		ActionType:      triage.ActionBumpVersion,
		ProposedCommand: "kubectl set image deployment/api-server api=redis:7.2.5-alpine -n payments",
		TargetImage:     "redis:7.2.5-alpine",
		Severity:        scanner.SeverityHigh,
		ConfidenceScore: 0.95,
	}

	proposal := engine.CreateProposal(issue, diagnosis)
	if proposal == nil {
		t.Fatal("CreateProposal returned nil")
	}
	if proposal.Status != StatusPending {
		t.Fatalf("expected StatusPending, got %v", proposal.Status)
	}

	// Human approves the version bump
	approved, err := engine.Approve(context.Background(), proposal.ID, "security-admin@kubebee.com")
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}
	if approved.Status != StatusApproved && approved.Status != StatusExecuting && approved.Status != StatusCompleted {
		t.Fatalf("unexpected status after approval: %v", approved.Status)
	}

	// Wait for async execution in engine worker
	time.Sleep(100 * time.Millisecond)

	current, ok := engine.GetProposal(proposal.ID)
	if !ok {
		t.Fatal("GetProposal returned false")
	}
	if current.Status != StatusCompleted {
		t.Fatalf("expected StatusCompleted after execution, got %v (error: %s)", current.Status, current.ExecutionError)
	}
	if current.VerificationStatus != VerificationStatusVerified {
		t.Fatalf("expected VerificationStatusVerified, got %v", current.VerificationStatus)
	}
}
