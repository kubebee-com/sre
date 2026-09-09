package triage

import (
	"context"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestRuleProviderCoversEverySupportedCategory(t *testing.T) {
	for _, category := range allSupportedRuleCategories() {
		t.Run(string(category), func(t *testing.T) {
			diagnosis, err := NewRuleBasedProvider("fixture-secret").Diagnose(context.Background(), &scanner.Issue{
				ID:        "fixture/" + string(category),
				Namespace: "sre-fixtures",
				Kind:      "Pod",
				Name:      "fixture",
				Category:  category,
				Severity:  scanner.SeverityMedium,
			})
			if err != nil {
				t.Fatalf("Diagnose() error = %v", err)
			}
			if diagnosis == nil || diagnosis.Summary == "" || diagnosis.RootCause == "" || diagnosis.RemediationPlan == "" || diagnosis.ActionType == "" || diagnosis.ProposedCommand == "" || diagnosis.ConfidenceScore <= 0 || diagnosis.ConfidenceScore > 1 {
				t.Fatalf("incomplete diagnosis: %#v", diagnosis)
			}
			if err := ValidateDiagnosis(diagnosis, "fixture/"+string(category)); err != nil {
				t.Fatalf("ValidateDiagnosis() error = %v, diagnosis = %#v", err, diagnosis)
			}
		})
	}
}

func allSupportedRuleCategories() []scanner.IssueCategory {
	return []scanner.IssueCategory{
		scanner.CategoryCrashLoop, scanner.CategoryOOMKilled, scanner.CategoryImagePull, scanner.CategoryFailedScheduling,
		scanner.CategoryContainerConfig, scanner.CategoryHighRestarts, scanner.CategoryPodLogError, scanner.CategoryPodFailed,
		scanner.CategoryPodEvicted, scanner.CategoryPodStuckTerminating, scanner.CategoryDeploymentMismatch,
		scanner.CategoryStatefulSetMismatch, scanner.CategoryDaemonSetMismatch, scanner.CategoryReplicaSetStuck,
		scanner.CategoryJobFailed, scanner.CategoryCronJobFailed, scanner.CategoryCronJobInvalid, scanner.CategoryCronJobSuspended,
		scanner.CategoryWorkloadDrift, scanner.CategoryServiceNoEndpoint, scanner.CategoryServiceEndpointError,
		scanner.CategoryServicePortMismatch, scanner.CategoryIngressBackendNotFound, scanner.CategoryIngressClassMissing,
		scanner.CategoryIngressPortInvalid, scanner.CategoryIngressTLSSecretMissing, scanner.CategoryNetworkPolicyOrphaned,
		scanner.CategoryNetworkPolicyWide, scanner.CategoryNodePressure, scanner.CategoryNodeNotReady,
		scanner.CategoryNodeNetworkUnavailable, scanner.CategoryNodeUnschedulable, scanner.CategoryNodeTaint,
		scanner.CategoryPVCPending, scanner.CategoryPVLost, scanner.CategoryPVCStorageClassMissing, scanner.CategoryPVSmallCapacity,
		scanner.CategoryPVReleased, scanner.CategoryPVFailed, scanner.CategoryStorageClassDefault, scanner.CategoryStorageClassDeprecated,
		scanner.CategoryStorageClassNoProvisioner, scanner.CategoryHPAScalingLimited, scanner.CategoryHPAMetricsUnavailable,
		scanner.CategoryHPATargetMissing, scanner.CategoryHPAMetricInvalid, scanner.CategoryPDBDisruptionsBlocked,
		scanner.CategoryPDBSelectorInvalid, scanner.CategoryPDBNoMatchingPods, scanner.CategoryConfigMapEmpty,
		scanner.CategoryConfigMapUnused, scanner.CategoryConfigMapTooLarge, scanner.CategoryWebhookServiceMissing,
		scanner.CategoryWebhookNoActivePods, scanner.CategoryWebhookTargetMissing, scanner.CategorySecurityPrivilege,
		scanner.CategorySecurityClusterBinding, scanner.CategoryEKSClusterHealth, scanner.CategoryWarningEvent,
		scanner.CategoryGatewayClassNotAccepted, scanner.CategoryGatewayNotAccepted, scanner.CategoryGatewayNotProgrammed,
		scanner.CategoryGatewayListenerInvalid, scanner.CategoryGatewaySpecInvalid, scanner.CategoryHTTPRouteNoParent,
		scanner.CategoryHTTPRouteParentNotAccepted, scanner.CategoryHTTPRouteRefsNotResolved, scanner.CategoryHTTPRouteBackendMissing,
		scanner.CategoryHTTPRouteBackendInvalid, scanner.CategoryReferenceGrantInvalid, scanner.CategoryReferenceGrantMissing,
		scanner.CategoryOLMResourceUnhealthy, scanner.CategoryIntegrationResourceUnhealthy, scanner.CategoryDynamicMalformed,
	}
}
