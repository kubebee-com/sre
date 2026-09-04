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
	// Pod Analyzers
	CategoryCrashLoop         IssueCategory = "CrashLoopBackOff"
	CategoryOOMKilled          IssueCategory = "OOMKilled"
	CategoryImagePull         IssueCategory = "ImagePullBackOff"
	CategoryFailedScheduling  IssueCategory = "FailedScheduling"
	CategoryContainerConfig   IssueCategory = "ContainerConfigError"
	CategoryHighRestarts      IssueCategory = "HighRestartCount"
	CategoryPodFailed         IssueCategory = "PodFailed"
	CategoryPodEvicted        IssueCategory = "PodEvicted"
	CategoryPodStuckTerminating IssueCategory = "PodStuckTerminating"

	// Workload Analyzers
	CategoryDeploymentMismatch IssueCategory = "DeploymentMismatch"
	CategoryStatefulSetMismatch IssueCategory = "StatefulSetMismatch"
	CategoryDaemonSetMismatch   IssueCategory = "DaemonSetMismatch"
	CategoryReplicaSetStuck     IssueCategory = "ReplicaSetStuck"
	CategoryJobFailed           IssueCategory = "JobFailed"
	CategoryCronJobFailed       IssueCategory = "CronJobFailed"

	// Service & Networking Analyzers
	CategoryServiceNoEndpoint   IssueCategory = "ServiceNoEndpoints"
	CategoryIngressBackendNotFound IssueCategory = "IngressBackendNotFound"
	CategoryIngressClassMissing IssueCategory = "IngressClassMissing"
	CategoryIngressTLSSecretMissing IssueCategory = "IngressTLSSecretMissing"
	CategoryNetworkPolicyOrphaned IssueCategory = "NetworkPolicyOrphaned"

	// Node & Infrastructure Analyzers
	CategoryNodePressure      IssueCategory = "NodePressure"
	CategoryNodeNotReady      IssueCategory = "NodeNotReady"
	CategoryPVCPending        IssueCategory = "PVCPending"
	CategoryPVLost            IssueCategory = "PVLost"
	CategoryHPAScalingLimited IssueCategory = "HPAScalingLimited"
	CategoryHPAMetricsUnavailable IssueCategory = "HPAMetricsUnavailable"
	CategoryPDBDisruptionsBlocked IssueCategory = "PDBDisruptionsBlocked"

	// Generic events
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

type AnalyzerInfo struct {
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	IssueCount  int    `json:"issue_count"`
}

type CleanablePod struct {
	Namespace    string     `json:"namespace"`
	Name         string     `json:"name"`
	Phase        string     `json:"phase"`
	Reason       string     `json:"reason"`
	Age          string     `json:"age"`
	RestartCount int32      `json:"restart_count"`
	IsStuck      bool       `json:"is_stuck"`
	DeletionTime *time.Time `json:"deletion_timestamp,omitempty"`
}

type CleanupReport struct {
	TargetPods   []string `json:"target_pods"`
	DeletedCount int      `json:"deleted_count"`
	FailedCount  int      `json:"failed_count"`
	Errors       []string `json:"errors,omitempty"`
	DryRun       bool     `json:"dry_run"`
}
