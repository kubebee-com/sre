package scanner

import (
	"context"
	"sort"
	"time"

	"github.com/kubebee-com/sre/pkg/scanplan"
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
	CategoryCrashLoop           IssueCategory = "CrashLoopBackOff"
	CategoryOOMKilled           IssueCategory = "OOMKilled"
	CategoryImagePull           IssueCategory = "ImagePullBackOff"
	CategoryFailedScheduling    IssueCategory = "FailedScheduling"
	CategoryContainerConfig     IssueCategory = "ContainerConfigError"
	CategoryHighRestarts        IssueCategory = "HighRestartCount"
	CategoryPodLogError         IssueCategory = "PodLogError"
	CategoryPodFailed           IssueCategory = "PodFailed"
	CategoryPodEvicted          IssueCategory = "PodEvicted"
	CategoryPodStuckTerminating IssueCategory = "PodStuckTerminating"

	// Workload Analyzers
	CategoryDeploymentMismatch  IssueCategory = "DeploymentMismatch"
	CategoryStatefulSetMismatch IssueCategory = "StatefulSetMismatch"
	CategoryDaemonSetMismatch   IssueCategory = "DaemonSetMismatch"
	CategoryReplicaSetStuck     IssueCategory = "ReplicaSetStuck"
	CategoryJobFailed           IssueCategory = "JobFailed"
	CategoryJobBackoffExceeded  IssueCategory = "JobBackoffLimitExceeded"
	CategoryJobDeadlineExceeded IssueCategory = "JobActiveDeadlineExceeded"
	CategoryCronJobFailed       IssueCategory = "CronJobFailed"
	CategoryCronJobInvalid      IssueCategory = "CronJobInvalidSchedule"
	CategoryCronJobSuspended    IssueCategory = "CronJobSuspended"
	CategoryCronJobMissed       IssueCategory = "CronJobMissedSchedule"
	CategoryWorkloadDrift       IssueCategory = "WorkloadSelectorDrift"

	// Service & Networking Analyzers
	CategoryServiceNoEndpoint       IssueCategory = "ServiceNoEndpoints"
	CategoryServiceEndpointError    IssueCategory = "ServiceEndpointError"
	CategoryServicePortMismatch     IssueCategory = "ServicePortMismatch"
	CategoryServiceExternalInvalid  IssueCategory = "ServiceExternalNameInvalid"
	CategoryIngressBackendNotFound  IssueCategory = "IngressBackendNotFound"
	CategoryIngressClassMissing     IssueCategory = "IngressClassMissing"
	CategoryIngressPortInvalid      IssueCategory = "IngressPortInvalid"
	CategoryIngressPathInvalid      IssueCategory = "IngressPathInvalid"
	CategoryIngressStatusPending    IssueCategory = "IngressStatusPending"
	CategoryIngressTLSSecretMissing IssueCategory = "IngressTLSSecretMissing"
	CategoryNetworkPolicyOrphaned   IssueCategory = "NetworkPolicyOrphaned"
	CategoryNetworkPolicyWide       IssueCategory = "NetworkPolicyWideSelector"

	// Node & Infrastructure Analyzers
	CategoryNodePressure              IssueCategory = "NodePressure"
	CategoryNodeNotReady              IssueCategory = "NodeNotReady"
	CategoryNodeNetworkUnavailable    IssueCategory = "NodeNetworkUnavailable"
	CategoryNodeUnschedulable         IssueCategory = "NodeUnschedulable"
	CategoryNodeTaint                 IssueCategory = "NodeTaint"
	CategoryPVCPending                IssueCategory = "PVCPending"
	CategoryPVLost                    IssueCategory = "PVLost"
	CategoryPVCStorageClassMissing    IssueCategory = "PVCStorageClassMissing"
	CategoryPVSmallCapacity           IssueCategory = "PVSmallCapacity"
	CategoryPVReleased                IssueCategory = "PVReleased"
	CategoryPVFailed                  IssueCategory = "PVFailed"
	CategoryStorageClassDefault       IssueCategory = "StorageClassMultipleDefaults"
	CategoryStorageClassDeprecated    IssueCategory = "StorageClassDeprecated"
	CategoryStorageClassNoProvisioner IssueCategory = "StorageClassNoProvisioner"
	CategoryHPAScalingLimited         IssueCategory = "HPAScalingLimited"
	CategoryHPAMetricsUnavailable     IssueCategory = "HPAMetricsUnavailable"
	CategoryHPATargetMissing          IssueCategory = "HPATargetMissing"
	CategoryHPAMetricInvalid          IssueCategory = "HPAMetricInvalid"
	CategoryPDBDisruptionsBlocked     IssueCategory = "PDBDisruptionsBlocked"
	CategoryPDBSelectorInvalid        IssueCategory = "PDBSelectorInvalid"
	CategoryPDBNoMatchingPods         IssueCategory = "PDBNoMatchingPods"

	// Configuration, admission, and security analyzers
	CategoryConfigMapEmpty            IssueCategory = "ConfigMapEmpty"
	CategoryConfigMapUnused           IssueCategory = "ConfigMapUnused"
	CategoryConfigMapTooLarge         IssueCategory = "ConfigMapTooLarge"
	CategoryConfigMapReferenceMissing IssueCategory = "ConfigMapReferenceMissing"
	CategoryWebhookServiceMissing     IssueCategory = "WebhookServiceMissing"
	CategoryWebhookNoActivePods       IssueCategory = "WebhookNoActivePods"
	CategoryWebhookTargetMissing      IssueCategory = "WebhookTargetMissing"
	CategorySecurityPrivilege         IssueCategory = "SecurityPrivilege"
	CategorySecurityClusterBinding    IssueCategory = "SecurityClusterBinding"
	CategoryEKSClusterHealth          IssueCategory = "EKSClusterHealth"
	CategoryPodVulnerability          IssueCategory = "PodVulnerability"
	CategoryClusterSecurityRisk       IssueCategory = "ClusterSecurityRisk"
	CategoryAppUpdateAvailable        IssueCategory = "AppUpdateAvailable"

	// Generic events
	CategoryWarningEvent IssueCategory = "WarningEvent"
)

const (
	maxIssueSummaryBytes     = 2 * 1024
	maxIssueDetailsBytes     = 16 * 1024
	maxIssueLogsSnippetBytes = 64 * 1024
	maxIssueSpecSnippetBytes = 16 * 1024
	maxIssueEventCount       = 32
	maxIssueEventBytes       = 2 * 1024
)

// AllIssueCategories returns the stable catalog consumed by providers and
// conformance tests. The returned slice is a new sorted copy on every call.
func AllIssueCategories() []IssueCategory {
	result := []IssueCategory{
		CategoryCrashLoop, CategoryOOMKilled, CategoryImagePull, CategoryFailedScheduling,
		CategoryContainerConfig, CategoryHighRestarts, CategoryPodLogError, CategoryPodFailed,
		CategoryPodEvicted, CategoryPodStuckTerminating,
		CategoryDeploymentMismatch, CategoryStatefulSetMismatch, CategoryDaemonSetMismatch,
		CategoryReplicaSetStuck, CategoryJobFailed, CategoryJobBackoffExceeded,
		CategoryJobDeadlineExceeded, CategoryCronJobFailed, CategoryCronJobInvalid,
		CategoryCronJobSuspended, CategoryCronJobMissed, CategoryWorkloadDrift,
		CategoryServiceNoEndpoint, CategoryServiceEndpointError, CategoryServicePortMismatch,
		CategoryServiceExternalInvalid, CategoryIngressBackendNotFound, CategoryIngressClassMissing,
		CategoryIngressPortInvalid, CategoryIngressPathInvalid, CategoryIngressStatusPending,
		CategoryIngressTLSSecretMissing, CategoryNetworkPolicyOrphaned, CategoryNetworkPolicyWide,
		CategoryNodePressure, CategoryNodeNotReady, CategoryNodeNetworkUnavailable,
		CategoryNodeUnschedulable, CategoryNodeTaint, CategoryPVCPending, CategoryPVLost,
		CategoryPVCStorageClassMissing, CategoryPVSmallCapacity, CategoryPVReleased,
		CategoryPVFailed, CategoryStorageClassDefault, CategoryStorageClassDeprecated,
		CategoryStorageClassNoProvisioner, CategoryHPAScalingLimited, CategoryHPAMetricsUnavailable,
		CategoryHPATargetMissing, CategoryHPAMetricInvalid, CategoryPDBDisruptionsBlocked,
		CategoryPDBSelectorInvalid, CategoryPDBNoMatchingPods, CategoryConfigMapEmpty,
		CategoryConfigMapUnused, CategoryConfigMapTooLarge, CategoryConfigMapReferenceMissing,
		CategoryWebhookServiceMissing, CategoryWebhookNoActivePods, CategoryWebhookTargetMissing,
		CategorySecurityPrivilege, CategorySecurityClusterBinding, CategoryEKSClusterHealth,
		CategoryPodVulnerability, CategoryClusterSecurityRisk, CategoryAppUpdateAvailable,
		CategoryWarningEvent, CategoryGatewayClassNotAccepted, CategoryGatewayNotAccepted,
		CategoryGatewayNotProgrammed, CategoryGatewayListenerInvalid, CategoryGatewaySpecInvalid,
		CategoryHTTPRouteNoParent, CategoryHTTPRouteParentNotAccepted, CategoryHTTPRouteRefsNotResolved,
		CategoryHTTPRouteBackendMissing, CategoryHTTPRouteBackendInvalid, CategoryReferenceGrantInvalid,
		CategoryReferenceGrantMissing, CategoryOLMResourceUnhealthy, CategoryIntegrationResourceUnhealthy,
		CategoryDynamicMalformed,
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

type Issue struct {
	AnalyzerNames         []string      `json:"analyzer_names,omitempty"`
	ID                    string        `json:"id"`
	Namespace             string        `json:"namespace"`
	Kind                  string        `json:"kind"`
	Name                  string        `json:"name"`
	TargetUID             string        `json:"target_uid,omitempty"`
	TargetResourceVersion string        `json:"target_resource_version,omitempty"`
	Severity              Severity      `json:"severity"`
	Category              IssueCategory `json:"category"`
	Summary               string        `json:"summary"`
	Details               string        `json:"details"`
	LogsSnippet           string        `json:"logs_snippet,omitempty"`
	Events                []string      `json:"events,omitempty"`
	SpecSnippet           string        `json:"spec_snippet,omitempty"`
	FirstObserved         time.Time     `json:"first_observed"`
	LastObserved          time.Time     `json:"last_observed"`
	Parent                *ResourceRef  `json:"parent,omitempty"`
	DocsURL               string        `json:"docs_url,omitempty"`
}

type ResourceRef struct {
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	UID       string `json:"uid,omitempty"`
}

type AnalyzerInfo struct {
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
	DocsURL     string `json:"docs_url,omitempty"`
	ParentKind  string `json:"parent_kind,omitempty"`
	Enabled     bool   `json:"enabled"`
	IssueCount  int    `json:"issue_count"`
}

type AnalyzerRun struct {
	Info       AnalyzerInfo `json:"info"`
	IssueCount int          `json:"issue_count"`
	Duration   string       `json:"duration"`
	Error      string       `json:"error,omitempty"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
}

type ScanReport struct {
	// Error prevents reconciliation when execution was canceled or incomplete.
	Error         string                  `json:"error,omitempty"`
	SchemaVersion string                  `json:"schema_version"`
	Scope         scanplan.EffectiveScope `json:"scope"`
	Issues        []*Issue                `json:"issues"`
	Analyzers     []AnalyzerRun           `json:"analyzers"`
	StartedAt     time.Time               `json:"started_at"`
	FinishedAt    time.Time               `json:"finished_at"`
	Duration      string                  `json:"duration"`
}

type Analyzer interface {
	Info() AnalyzerInfo
	Analyze(context.Context, string) ([]*Issue, error)
}

type CleanablePod struct {
	Namespace             string     `json:"namespace"`
	Name                  string     `json:"name"`
	TargetUID             string     `json:"target_uid"`
	TargetResourceVersion string     `json:"target_resource_version"`
	Phase                 string     `json:"phase"`
	Reason                string     `json:"reason"`
	Age                   string     `json:"age"`
	RestartCount          int32      `json:"restart_count"`
	IsStuck               bool       `json:"is_stuck"`
	DeletionTime          *time.Time `json:"deletion_timestamp,omitempty"`
}

type CleanupReport struct {
	TargetPods    []string `json:"target_pods"`
	CandidatePods []string `json:"candidate_pods,omitempty"`
	DeletedCount  int      `json:"deleted_count"`
	FailedCount   int      `json:"failed_count"`
	Errors        []string `json:"errors,omitempty"`
	DryRun        bool     `json:"dry_run"`
}
