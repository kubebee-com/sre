package investigation

import (
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/triage"
)

const (
	RubricVersion = "diagnostic-rubric/v1"
	PromptVersion = "investigation/v2"
)

type Status string

const (
	Hypothesis    Status = "HYPOTHESIS"
	Inconclusive  Status = "INCONCLUSIVE"
	NeedsEvidence Status = "NEEDS_EVIDENCE"
	Corroborated  Status = "CORROBORATED"
)

type EvidenceSnapshot struct {
	Ref         incident.ItemRef    `json:"ref"`
	Observation privacy.Observation `json:"observation"`
}
type Alternative struct {
	CauseCode              privacy.Code       `json:"cause_code"`
	DiscriminatingEvidence []incident.ItemRef `json:"discriminating_evidence"`
}
type Check struct {
	Kind           string `json:"kind"`
	ResourceHandle string `json:"resource_handle"`
}
type Round struct {
	ProviderLatencyMS int64                      `json:"provider_latency_ms"`
	Usage             *triage.ProviderTokenUsage `json:"usage"`
	Number            int                        `json:"number"`
	Status            Status                     `json:"status"`
	Reason            string                     `json:"reason"`
	EvidenceCount     int                        `json:"evidence_count"`
	ChecksRequested   int                        `json:"checks_requested"`
}
type Conclusion struct {
	RequestedChecks       []Check            `json:"requested_checks,omitempty"`
	CauseCode             privacy.Code       `json:"cause_code"`
	ResourceHandle        string             `json:"resource_handle"`
	SupportingEvidence    []incident.ItemRef `json:"supporting_evidence"`
	ContradictingEvidence []incident.ItemRef `json:"contradicting_evidence"`
	Alternatives          []Alternative      `json:"alternatives"`
}
type Assessment struct {
	Status     Status     `json:"status"`
	ReasonCode string     `json:"reason_code"`
	Conclusion Conclusion `json:"conclusion"`
}
type RunResult struct {
	Rounds             []Round            `json:"rounds,omitempty"`
	KnowledgeVersions  []incident.ItemRef `json:"knowledge_versions,omitempty"`
	EnvironmentVersion int64              `json:"environment_version,omitempty"`
	RunID              string             `json:"run_id"`
	ProfileID          string             `json:"profile_id"`
	ProfileVersion     string             `json:"profile_version"`
	PrivacyVersion     string             `json:"privacy_version"`
	PromptVersion      string             `json:"prompt_version"`
	RubricVersion      string             `json:"rubric_version"`
	Assessment         Assessment         `json:"assessment"`
}
