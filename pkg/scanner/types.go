package scanner

import (
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

type IssueCategory string

const (
	CategoryCrashLoop         IssueCategory = "CrashLoopBackOff"
	CategoryOOMKilled          IssueCategory = "OOMKilled"
	CategoryImagePull         IssueCategory = "ImagePullBackOff"
	CategoryFailedScheduling  IssueCategory = "FailedScheduling"
	CategoryContainerConfig   IssueCategory = "ContainerConfigError"
	CategoryHighRestarts      IssueCategory = "HighRestartCount"
	CategoryPodFailed         IssueCategory = "PodFailed"
	CategoryNodePressure      IssueCategory = "NodePressure"
	CategoryPVCPending        IssueCategory = "PVCPending"
	CategoryServiceNoEndpoint IssueCategory = "ServiceNoEndpoints"
	CategoryWarningEvent      IssueCategory = "WarningEvent"
)

type Issue struct {
	ID            string        `json:"id"`
	Namespace     string        `json:"namespace"`
	Kind          string        `json:"kind"`
	Name          string        `json:"name"`
	Severity      Severity      `json:"severity"`
	Category      IssueCategory `json:"category"`
	Summary       string        `json:"summary"`
	Details       string        `json:"details"`
	LogsSnippet   string        `json:"logs_snippet,omitempty"`
	Events        []string      `json:"events,omitempty"`
	SpecSnippet   string        `json:"spec_snippet,omitempty"`
	FirstObserved time.Time     `json:"first_observed"`
	LastObserved  time.Time     `json:"last_observed"`
}
