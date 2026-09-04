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
	ActionGitOpsPR         ActionType = "GitOpsPR"
	ActionManual           ActionType = "Manual"
)

type Diagnosis struct {
	IssueID         string           `json:"issue_id"`
	Summary         string           `json:"summary"`
	RootCause       string           `json:"root_cause"`
	Severity        scanner.Severity `json:"severity"`
	RemediationPlan string           `json:"remediation_plan"`
	ActionType      ActionType       `json:"action_type"`
	ProposedCommand string           `json:"proposed_command"`
	ConfidenceScore float64          `json:"confidence_score"`
	ProviderName    string           `json:"provider_name"`
}
