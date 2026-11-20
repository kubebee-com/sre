package agentharness

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestParseHarnessKindDefaultsToCodex(t *testing.T) {
	got, err := ParseHarnessKind("")
	if err != nil {
		t.Fatalf("ParseHarnessKind(\"\") error = %v", err)
	}
	if got != HarnessCodex {
		t.Fatalf("default harness = %q, want %q", got, HarnessCodex)
	}

	got, err = ParseHarnessKind("AGY")
	if err != nil {
		t.Fatalf("ParseHarnessKind(\"AGY\") error = %v", err)
	}
	if got != HarnessAgy {
		t.Fatalf("agy harness = %q, want %q", got, HarnessAgy)
	}

	if _, err := ParseHarnessKind("unknown-cli"); err == nil {
		t.Fatal("expected error for unsupported harness")
	}
}

func TestBuildCommandSpecCodexAndAgy(t *testing.T) {
	cfg := Config{
		Enabled:         true,
		Model:           "gpt-6-luna",
		ReasoningEffort: "high",
	}

	codexPlan, err := BuildCommandSpec(cfg, HarnessCodex, PhasePlan, "diagnose")
	if err != nil {
		t.Fatalf("codex plan error = %v", err)
	}
	if codexPlan.Binary != "codex" {
		t.Fatalf("codex binary = %q, want codex", codexPlan.Binary)
	}
	joined := strings.Join(codexPlan.Args, " ")
	for _, want := range []string{"exec", "--sandbox read-only", "--model gpt-6-luna", `model_reasoning_effort="high"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("codex plan args %q missing %q", joined, want)
		}
	}

	codexApply, err := BuildCommandSpec(cfg, HarnessCodex, PhaseApply, "apply")
	if err != nil {
		t.Fatalf("codex apply error = %v", err)
	}
	if !strings.Contains(strings.Join(codexApply.Args, " "), "--sandbox workspace-write") {
		t.Errorf("codex apply args %q missing workspace-write sandbox", strings.Join(codexApply.Args, " "))
	}

	agyPlan, err := BuildCommandSpec(cfg, HarnessAgy, PhasePlan, "diagnose")
	if err != nil {
		t.Fatalf("agy plan error = %v", err)
	}
	if agyPlan.Binary != "agy" {
		t.Fatalf("agy binary = %q, want agy", agyPlan.Binary)
	}
	agyJoined := strings.Join(agyPlan.Args, " ")
	for _, want := range []string{"--print", "--mode plan", "--sandbox", "--output-format json", "--json-schema", "--model gpt-6-luna", "--effort high"} {
		if !strings.Contains(agyJoined, want) {
			t.Errorf("agy plan args %q missing %q", agyJoined, want)
		}
	}

	agyApply, err := BuildCommandSpec(cfg, HarnessAgy, PhaseApply, "apply")
	if err != nil {
		t.Fatalf("agy apply error = %v", err)
	}
	if !strings.Contains(strings.Join(agyApply.Args, " "), "--mode accept-edits") {
		t.Errorf("agy apply args %q missing accept-edits mode", strings.Join(agyApply.Args, " "))
	}
}

func TestBuildJobSpecSecurityAndRuntimeClass(t *testing.T) {
	cfg := Config{
		Enabled:          true,
		RuntimeClassName: "gvisor",
		Namespace:        "sre",
		GitOpsSecretName: "sre-gitops-token",
	}
	runner := NewK8sJobRunner(fake.NewSimpleClientset(), cfg)

	planJob, err := runner.BuildJobSpec("sre-solver-plan-codex-1234", "prompt-cm", HarnessCodex, PhasePlan, map[string]string{"sre.kubebee.com/issue-id": "issue-1"})
	if err != nil {
		t.Fatalf("BuildJobSpec(plan) error = %v", err)
	}
	spec := planJob.Spec.Template.Spec
	if spec.RuntimeClassName == nil || *spec.RuntimeClassName != "gvisor" {
		t.Fatalf("RuntimeClassName = %v, want gvisor", spec.RuntimeClassName)
	}
	if spec.ServiceAccountName != DefaultPlanServiceAccount {
		t.Fatalf("plan ServiceAccountName = %q, want %q", spec.ServiceAccountName, DefaultPlanServiceAccount)
	}
	if spec.SecurityContext == nil || spec.SecurityContext.RunAsNonRoot == nil || !*spec.SecurityContext.RunAsNonRoot {
		t.Fatal("expected pod RunAsNonRoot=true")
	}
	c := spec.Containers[0]
	if c.SecurityContext == nil || c.SecurityContext.ReadOnlyRootFilesystem == nil || !*c.SecurityContext.ReadOnlyRootFilesystem {
		t.Fatal("expected container ReadOnlyRootFilesystem=true")
	}
	if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
		t.Fatal("expected AllowPrivilegeEscalation=false")
	}
	for _, env := range c.Env {
		if env.Name == "GITOPS_TOKEN" {
			t.Fatal("plan phase job must NOT mount GITOPS_TOKEN")
		}
	}

	applyJob, err := runner.BuildJobSpec("sre-solver-apply-agy-5678", "prompt-cm", HarnessAgy, PhaseApply, map[string]string{"sre.kubebee.com/proposal-id": "prop-1"})
	if err != nil {
		t.Fatalf("BuildJobSpec(apply) error = %v", err)
	}
	if applyJob.Spec.Template.Spec.ServiceAccountName != DefaultApplyServiceAccount {
		t.Fatalf("apply ServiceAccountName = %q, want %q", applyJob.Spec.Template.Spec.ServiceAccountName, DefaultApplyServiceAccount)
	}
	foundGitOps := false
	for _, env := range applyJob.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "GITOPS_TOKEN" {
			foundGitOps = true
		}
	}
	if !foundGitOps {
		t.Fatal("apply phase job should mount configured GITOPS_TOKEN secret")
	}
}

func TestParseSolutionOutputRedactsSecretsAndUnwrapsEnvelope(t *testing.T) {
	inner := map[string]any{
		"summary":           "Align Tempo distributor containerPort 9095",
		"root_cause":        "Chart omits containerPort 9095; token=super-secret-value-123",
		"remediation_plan":  "Patch Deployment to declare port 9095",
		"action_type":       "AgentRemediation",
		"proposed_commands": []string{"kubectl -n tracing get svc tracing-distributor"},
		"gitops_patch":      "apps/tracing/fluxcd.yaml: +containerPort: 9095",
		"verification_plan": "Verify endpoints and rerun scanner",
		"rollback_plan":     "git revert HEAD",
		"confidence_score":  0.92,
	}
	innerJSON, _ := json.Marshal(inner)
	wrapped, _ := json.Marshal(map[string]any{"result": string(innerJSON)})

	sol, err := ParseSolutionOutput(string(wrapped), HarnessAgy, "gvisor", "super-secret-value-123")
	if err != nil {
		t.Fatalf("ParseSolutionOutput error = %v", err)
	}
	if strings.Contains(sol.RootCause, "super-secret-value-123") {
		t.Fatalf("secret leaked in root_cause: %q", sol.RootCause)
	}
	if sol.ActionType != triage.ActionAgentRemediation {
		t.Fatalf("ActionType = %q, want AgentRemediation", sol.ActionType)
	}
	if sol.Harness != HarnessAgy || sol.SandboxRuntime != "gvisor" {
		t.Fatalf("unexpected metadata: harness=%q runtime=%q", sol.Harness, sol.SandboxRuntime)
	}
}

func TestK8sJobRunnerCreateAndApplyLifecycle(t *testing.T) {
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		job.Status.Succeeded = 1
		// Seed a matching pod directly in the object tracker to avoid re-entering client.Fake mutex.
		_ = client.Tracker().Add(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      job.Name + "-pod",
				Namespace: job.Namespace,
				Labels:    map[string]string{"job-name": job.Name},
			},
		})
		return false, nil, nil
	})

	runner := NewK8sJobRunner(client, Config{
		Enabled:          true,
		Namespace:        "sre",
		RuntimeClassName: "gvisor",
		Timeout:          30 * time.Second,
	})
	runner.pollInterval = 5 * time.Millisecond
	runner.logFetcher = func(ctx context.Context, namespace, podName, container string) (string, error) {
		if strings.Contains(podName, "-plan-") {
			return `{"summary":"Fix port mismatch","root_cause":"Missing containerPort 9095","remediation_plan":"Add port 9095 to Deployment","action_type":"AgentRemediation","proposed_commands":["kubectl -n tracing patch deploy tracing-distributor"],"verification_plan":"Check endpoints","rollback_plan":"Revert patch","confidence_score":0.95}`, nil
		}
		return "Applied patch and verified tracing-distributor endpoints are healthy.", nil
	}

	issue := &scanner.Issue{
		ID:        "issue-tempo-9095",
		Namespace: "tracing",
		Kind:      "Service",
		Name:      "tracing-distributor",
		Category:  scanner.CategoryServicePortMismatch,
		Severity:  scanner.SeverityHigh,
		Summary:   "Service tracing-distributor target port 9095 is not declared",
	}

	sol, err := runner.CreateSolution(context.Background(), issue, "")
	if err != nil {
		t.Fatalf("CreateSolution() error = %v", err)
	}
	if sol.Harness != HarnessCodex {
		t.Fatalf("default CreateSolution harness = %q, want codex", sol.Harness)
	}
	if sol.JobName == "" || !strings.HasPrefix(sol.JobName, "sre-solver-plan-codex-") {
		t.Fatalf("unexpected JobName = %q", sol.JobName)
	}
	diag := sol.ToDiagnosis(issue)
	if diag.ActionType != triage.ActionAgentRemediation || diag.AgentHarness != "codex" || diag.SandboxRuntime != "gvisor" {
		t.Fatalf("unexpected Diagnosis = %+v", diag)
	}

	out, err := runner.ApplySolution(context.Background(), ApplyRequest{
		ProposalID:       "prop-123",
		IssueID:          issue.ID,
		Namespace:        issue.Namespace,
		Kind:             issue.Kind,
		Name:             issue.Name,
		ApprovedBy:       "kevin",
		Harness:          HarnessCodex,
		Summary:          sol.Summary,
		RootCause:        sol.RootCause,
		RemediationPlan:  sol.RemediationPlan,
		ProposedCommands: sol.ProposedCommands,
		VerificationPlan: sol.VerificationPlan,
		RollbackPlan:     sol.RollbackPlan,
	})
	if err != nil {
		t.Fatalf("ApplySolution() error = %v", err)
	}
	if !strings.Contains(out, "verified tracing-distributor endpoints") {
		t.Fatalf("unexpected ApplySolution output: %q", out)
	}
}
