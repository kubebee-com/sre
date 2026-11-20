package agentharness

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

// HarnessKind identifies which AI coding agent CLI executes inside the sandbox.
type HarnessKind string

const (
	// HarnessCodex uses OpenAI Codex CLI (default).
	HarnessCodex HarnessKind = "codex"
	// HarnessAgy uses the `agy` CLI harness.
	HarnessAgy HarnessKind = "agy"
)

// SandboxMode controls how the agent harness process is isolated and launched.
type SandboxMode string

const (
	// SandboxModeK8sJob runs each agent invocation inside an ephemeral hardened
	// Kubernetes Job (with gVisor/Kata RuntimeClass by default).
	SandboxModeK8sJob SandboxMode = "k8s-job"
	// SandboxModeLocal executes the harness binary locally (for dev/CLI use).
	SandboxModeLocal SandboxMode = "local"
	// SandboxModeDisabled disables agent solution generation and execution.
	SandboxModeDisabled SandboxMode = "disabled"
)

// Phase separates read-only investigation/planning from approval-gated execution.
type Phase string

const (
	PhasePlan  Phase = "plan"
	PhaseApply Phase = "apply"
)

const (
	DefaultHarness               = HarnessCodex
	DefaultRuntimeClassName      = "gvisor"
	DefaultSandboxImage          = "ghcr.io/kubebee-com/sre-agent-sandbox:latest"
	DefaultSandboxNamespace      = "sre"
	DefaultPlanServiceAccount    = "sre-agent-solver-ro"
	DefaultApplyServiceAccount   = "sre-agent-solver-exec"
	DefaultOpenAISecretName      = "sre-openai-secrets"
	DefaultTimeout               = 10 * time.Minute
	DefaultTTLSecondsAfterFinish = int32(600)
	DefaultCPURequest            = "250m"
	DefaultCPULimit              = "2"
	DefaultMemoryRequest         = "512Mi"
	DefaultMemoryLimit           = "2Gi"
	MaxCapturedLogBytes          = 512 * 1024
)

// Config controls how Kubebee launches AI agent harnesses to create solutions
// and apply approved remediations.
type Config struct {
	Enabled                 bool
	DefaultHarness          HarnessKind
	AllowedHarnesses        []HarnessKind
	SandboxMode             SandboxMode
	Namespace               string
	Image                   string
	RuntimeClassName        string
	PlanServiceAccount      string
	ApplyServiceAccount     string
	OpenAISecretName        string
	GitOpsRepoURL           string
	GitOpsSecretName        string
	Timeout                 time.Duration
	TTLSecondsAfterFinished int32
	CPURequest              string
	CPULimit                string
	MemoryRequest           string
	MemoryLimit             string
	CodexBinary             string
	AgyBinary               string
	Model                   string
	ReasoningEffort         string
	APIEndpoint             string
	SecretValues            []string
}

// Normalized returns a copy of Config populated with safe defaults.
func (c Config) Normalized() Config {
	out := c
	if out.DefaultHarness == "" {
		out.DefaultHarness = DefaultHarness
	} else {
		out.DefaultHarness = HarnessKind(strings.ToLower(strings.TrimSpace(string(out.DefaultHarness))))
	}
	if len(out.AllowedHarnesses) == 0 {
		out.AllowedHarnesses = []HarnessKind{HarnessCodex, HarnessAgy}
	}
	if out.SandboxMode == "" {
		if out.Enabled {
			out.SandboxMode = SandboxModeK8sJob
		} else {
			out.SandboxMode = SandboxModeDisabled
		}
	} else {
		out.SandboxMode = SandboxMode(strings.ToLower(strings.TrimSpace(string(out.SandboxMode))))
	}
	if strings.TrimSpace(out.Namespace) == "" {
		out.Namespace = DefaultSandboxNamespace
	}
	if strings.TrimSpace(out.Image) == "" {
		out.Image = DefaultSandboxImage
	}
	if strings.TrimSpace(out.PlanServiceAccount) == "" {
		out.PlanServiceAccount = DefaultPlanServiceAccount
	}
	if strings.TrimSpace(out.ApplyServiceAccount) == "" {
		out.ApplyServiceAccount = DefaultApplyServiceAccount
	}
	if strings.TrimSpace(out.OpenAISecretName) == "" {
		out.OpenAISecretName = DefaultOpenAISecretName
	}
	if out.Timeout <= 0 {
		out.Timeout = DefaultTimeout
	}
	if out.TTLSecondsAfterFinished <= 0 {
		out.TTLSecondsAfterFinished = DefaultTTLSecondsAfterFinish
	}
	if strings.TrimSpace(out.CPURequest) == "" {
		out.CPURequest = DefaultCPURequest
	}
	if strings.TrimSpace(out.CPULimit) == "" {
		out.CPULimit = DefaultCPULimit
	}
	if strings.TrimSpace(out.MemoryRequest) == "" {
		out.MemoryRequest = DefaultMemoryRequest
	}
	if strings.TrimSpace(out.MemoryLimit) == "" {
		out.MemoryLimit = DefaultMemoryLimit
	}
	if strings.TrimSpace(out.CodexBinary) == "" {
		out.CodexBinary = "codex"
	}
	if strings.TrimSpace(out.AgyBinary) == "" {
		out.AgyBinary = "agy"
	}
	return out
}

// Validate checks configuration invariants before starting the runner.
func (c Config) Validate() error {
	norm := c.Normalized()
	if !norm.Enabled || norm.SandboxMode == SandboxModeDisabled {
		return nil
	}
	if _, err := ParseHarnessKind(string(norm.DefaultHarness)); err != nil {
		return err
	}
	switch norm.SandboxMode {
	case SandboxModeK8sJob, SandboxModeLocal:
	default:
		return fmt.Errorf("unsupported agent sandbox mode %q (want k8s-job or local)", norm.SandboxMode)
	}
	return nil
}

// ParseHarnessKind validates and normalizes a user-supplied harness identifier.
// An empty string selects the default harness ("codex").
func ParseHarnessKind(raw string) (HarnessKind, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return DefaultHarness, nil
	}
	switch HarnessKind(trimmed) {
	case HarnessCodex, HarnessAgy:
		return HarnessKind(trimmed), nil
	default:
		return "", fmt.Errorf("unsupported agent harness %q (supported: codex, agy)", raw)
	}
}

// ResolveHarness resolves an explicit request harness against the configured
// default and allowlist.
func (c Config) ResolveHarness(requested string) (HarnessKind, error) {
	norm := c.Normalized()
	var kind HarnessKind
	var err error
	if strings.TrimSpace(requested) == "" {
		kind = norm.DefaultHarness
	} else {
		kind, err = ParseHarnessKind(requested)
		if err != nil {
			return "", err
		}
	}
	for _, allowed := range norm.AllowedHarnesses {
		if allowed == kind {
			return kind, nil
		}
	}
	return "", fmt.Errorf("agent harness %q is not enabled in this cluster", kind)
}

// Solution is the structured remediation plan generated by a read-only agent
// run for human review prior to approval.
type Solution struct {
	Harness          HarnessKind       `json:"harness"`
	SandboxRuntime   string            `json:"sandbox_runtime"`
	Summary          string            `json:"summary"`
	RootCause        string            `json:"root_cause"`
	RemediationPlan  string            `json:"remediation_plan"`
	ActionType       triage.ActionType `json:"action_type"`
	ProposedCommands []string          `json:"proposed_commands,omitempty"`
	GitOpsPatch      string            `json:"gitops_patch,omitempty"`
	VerificationPlan string            `json:"verification_plan,omitempty"`
	RollbackPlan     string            `json:"rollback_plan,omitempty"`
	ConfidenceScore  float64           `json:"confidence_score"`
	JobName          string            `json:"job_name,omitempty"`
	RawOutput        string            `json:"-"`
}

// ToDiagnosis converts a reviewed agent Solution into a Kubebee Diagnosis so it
// flows seamlessly through the existing Proposal / Approve / Reject workflow.
func (s *Solution) ToDiagnosis(issue *scanner.Issue) *triage.Diagnosis {
	if s == nil {
		return nil
	}
	issueID := ""
	severity := scanner.SeverityHigh
	if issue != nil {
		issueID = issue.ID
		if issue.Severity != "" {
			severity = issue.Severity
		}
	}
	actionType := s.ActionType
	if actionType == "" {
		actionType = triage.ActionAgentRemediation
	}
	proposedCmd := fmt.Sprintf("# agent-harness %s (%s): execute approved plan", s.Harness, s.SandboxRuntime)
	if actionType != triage.ActionAgentRemediation && len(s.ProposedCommands) > 0 {
		proposedCmd = s.ProposedCommands[0]
	}
	providerName := fmt.Sprintf("Agent Harness (%s / %s)", s.Harness, s.SandboxRuntime)
	return &triage.Diagnosis{
		IssueID:          issueID,
		Summary:          s.Summary,
		RootCause:        s.RootCause,
		Severity:         severity,
		RemediationPlan:  s.RemediationPlan,
		ActionType:       actionType,
		ProposedCommand:  proposedCmd,
		ConfidenceScore:  s.ConfidenceScore,
		ProviderName:     providerName,
		AgentHarness:     string(s.Harness),
		SandboxRuntime:   s.SandboxRuntime,
		ProposedCommands: append([]string(nil), s.ProposedCommands...),
		GitOpsPatch:      s.GitOpsPatch,
		VerificationPlan: s.VerificationPlan,
		RollbackPlan:     s.RollbackPlan,
		AgentJobName:     s.JobName,
	}
}

// ApplyRequest describes an approved proposal to be executed by a sandboxed
// AI agent harness.
type ApplyRequest struct {
	ProposalID       string
	IssueID          string
	Namespace        string
	Kind             string
	Name             string
	ApprovedBy       string
	Harness          HarnessKind
	Summary          string
	RootCause        string
	RemediationPlan  string
	ProposedCommand  string
	ProposedCommands []string
	GitOpsPatch      string
	VerificationPlan string
	RollbackPlan     string
}

// Runner creates solutions (Phase 1, read-only) and executes approved
// solutions (Phase 2, approval-gated) using a sandboxed AI agent harness.
type Runner interface {
	Config() Config
	CreateSolution(ctx context.Context, issue *scanner.Issue, harness HarnessKind) (*Solution, error)
	ApplySolution(ctx context.Context, req ApplyRequest) (string, error)
}
