package triage

import (
	"github.com/kubebee-com/sre/pkg/scanner"
)

type ActionType string

const (
	ActionRestartPod       ActionType = "RestartPod"
	ActionDeleteFailedPod  ActionType = "DeleteFailedPod"
	ActionScaleWorkload    ActionType = "ScaleWorkload"
	ActionRolloutRestart   ActionType = "RolloutRestart"
	ActionCordonNode       ActionType = "CordonNode"
	ActionCleanupPods      ActionType = "CleanupPods"
	ActionBumpVersion      ActionType = "BumpVersion"
	ActionUpgradeApp       ActionType = "UpgradeApp"
	ActionGitOpsPR         ActionType = "GitOpsPR"
	ActionAgentRemediation ActionType = "AgentRemediation"
	ActionManual           ActionType = "Manual"
)

type Diagnosis struct {
	IssueID          string           `json:"issue_id"`
	Summary          string           `json:"summary"`
	RootCause        string           `json:"root_cause"`
	Severity         scanner.Severity `json:"severity"`
	RemediationPlan  string           `json:"remediation_plan"`
	ActionType       ActionType       `json:"action_type"`
	ProposedCommand  string           `json:"proposed_command"`
	TargetImage      string           `json:"target_image,omitempty"`
	TargetVersion    string           `json:"target_version,omitempty"`
	TargetReplicas   *int32           `json:"target_replicas,omitempty"`
	ConfidenceScore  float64          `json:"confidence_score"`
	ProviderName     string           `json:"provider_name"`
	AgentHarness     string           `json:"agent_harness,omitempty"`
	SandboxRuntime   string           `json:"sandbox_runtime,omitempty"`
	ProposedCommands []string         `json:"proposed_commands,omitempty"`
	GitOpsPatch      string           `json:"gitops_patch,omitempty"`
	VerificationPlan string           `json:"verification_plan,omitempty"`
	RollbackPlan     string           `json:"rollback_plan,omitempty"`
	AgentJobName     string           `json:"agent_job_name,omitempty"`
}
