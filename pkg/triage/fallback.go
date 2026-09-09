package triage

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

type RuleBasedProvider struct {
	redactor *sanitizer.Redactor
}

func NewRuleBasedProvider(secretValues ...string) *RuleBasedProvider {
	return &RuleBasedProvider{redactor: sanitizer.NewRedactor(secretValues...)}
}

func (p *RuleBasedProvider) Name() string {
	return "Rule-Based SRE Engine"
}

type ruleSpec struct {
	summary      string
	rootCause    string
	remediation  string
	action       ActionType
	resource     string
	commandStyle string
}

func ruleSpecFor(category scanner.IssueCategory) ruleSpec {
	manual := func(summary, rootCause, remediation, resource string) ruleSpec {
		return ruleSpec{summary: summary, rootCause: rootCause, remediation: remediation, action: ActionManual, resource: resource, commandStyle: "describe"}
	}
	switch category {
	case scanner.CategoryCrashLoop:
		return ruleSpec{"Repeated application crash", "The container is repeatedly exiting or failing its startup/readiness checks.", "Inspect logs and probe configuration, then restart the pod after correcting transient state.", ActionRestartPod, "pod", "describe"}
	case scanner.CategoryOOMKilled:
		return ruleSpec{"Memory limit exceeded", "The container exceeded its cgroup memory limit and was terminated by the kernel.", "Increase memory requests and limits in the workload manifest, then restart the workload.", ActionGitOpsPR, "pod", "describe"}
	case scanner.CategoryImagePull:
		return ruleSpec{"Container image could not be pulled", "The node could not resolve, authenticate to, or fetch the configured image reference.", "Verify the image reference, registry availability, and imagePullSecrets through the deployment source.", ActionManual, "pod", "describe"}
	case scanner.CategoryFailedScheduling:
		return manual("Pod cannot be scheduled", "The scheduler found no node satisfying the pod's resource, affinity, taint, or topology constraints.", "Inspect scheduler events and adjust capacity or placement constraints in the workload manifest.", "pod")
	case scanner.CategoryContainerConfig:
		return manual("Container configuration is invalid", "A referenced image, command, environment value, volume, or security setting cannot be assembled by the kubelet.", "Inspect the pod events and correct the referenced configuration in GitOps.", "pod")
	case scanner.CategoryHighRestarts:
		return manual("Container restart rate is high", "The container has restarted repeatedly in the observation window, indicating an unstable workload or probe.", "Review current and previous logs and correct the failure before choosing a restart action.", "pod")
	case scanner.CategoryPodLogError:
		return manual("Pod logs contain an error signal", "Recent container output contains an error or panic associated with the reported pod.", "Inspect bounded current and previous logs and correct the application or configuration fault.", "pod")
	case scanner.CategoryPodFailed:
		return ruleSpec{"Pod terminated with failure", "The pod reached a failed phase and will not recover without controller or operator action.", "Inspect the terminal status and delete only the failed pod so its controller can recreate it when appropriate.", ActionDeleteFailedPod, "pod", "describe"}
	case scanner.CategoryPodEvicted:
		return ruleSpec{"Pod was evicted", "The node evicted the pod under resource or storage pressure.", "Check node headroom and workload requests, then remove the terminal pod after preserving its evidence.", ActionDeleteFailedPod, "pod", "describe"}
	case scanner.CategoryPodStuckTerminating:
		return manual("Pod is stuck terminating", "A finalizer, volume detach, or container runtime operation is preventing normal termination.", "Inspect finalizers and volume attachment state before taking any deletion action.", "pod")
	case scanner.CategoryDeploymentMismatch:
		return ruleSpec{"Deployment replica count is degraded", "The deployment's observed replicas do not satisfy its desired state.", "Inspect the owning ReplicaSet and events, then use a controlled rollout restart after fixing the underlying cause.", ActionRolloutRestart, "deployment", "describe"}
	case scanner.CategoryStatefulSetMismatch:
		return manual("StatefulSet replica count is degraded", "One or more stateful replicas are unavailable or cannot attach their persistent state.", "Inspect pod scheduling, volume claims, and ordered rollout status before changing the workload.", "statefulset")
	case scanner.CategoryDaemonSetMismatch:
		return manual("DaemonSet coverage is degraded", "The daemonset cannot place the expected pod on one or more eligible nodes.", "Inspect node taints, selectors, tolerations, and daemonset events.", "daemonset")
	case scanner.CategoryReplicaSetStuck:
		return manual("ReplicaSet is not progressing", "The ReplicaSet cannot create or keep the desired number of pods ready.", "Inspect pod events, admission errors, and the owning workload template.", "replicaset")
	case scanner.CategoryJobFailed:
		return manual("Job exceeded its failure budget", "The job exhausted its retry budget or active deadline without completing.", "Inspect bounded job logs and events, fix the input or code, and rerun through the workload source.", "job")
	case scanner.CategoryCronJobFailed:
		return manual("CronJob execution failed", "A scheduled job failed or could not complete successfully.", "Inspect the failed job, its logs, and schedule policy before the next run.", "cronjob")
	case scanner.CategoryCronJobInvalid:
		return manual("CronJob schedule is invalid", "The CronJob schedule cannot be parsed or does not express the intended cadence.", "Correct the schedule in the workload manifest and verify the next scheduled run.", "cronjob")
	case scanner.CategoryCronJobSuspended:
		return manual("CronJob is suspended", "The CronJob suspension flag prevents new jobs from being created.", "Confirm the pause is intentional and update the source manifest if scheduling should resume.", "cronjob")
	case scanner.CategoryWorkloadDrift:
		return ruleSpec{"Workload selector or template drift detected", "The workload selector and pod template no longer describe the same set of pods.", "Reconcile the selector and template through GitOps before attempting a rollout.", ActionGitOpsPR, "deployment", "describe"}
	case scanner.CategoryServiceNoEndpoint:
		return ruleSpec{"Service has no ready endpoints", "The service selector does not currently resolve to ready serving pods.", "Verify selectors, pod labels, readiness probes, and endpoint readiness conditions.", ActionManual, "service", "describe"}
	case scanner.CategoryServiceEndpointError:
		return manual("Service endpoints are invalid", "The service endpoint objects contain addresses or conditions that do not represent a usable backend.", "Inspect endpoint and EndpointSlice conditions alongside the selected pods.", "service")
	case scanner.CategoryServicePortMismatch:
		return manual("Service port does not match its backend", "The service target port cannot be resolved on the selected pods or endpoint slices.", "Align service ports and container ports through the workload source.", "service")
	case scanner.CategoryIngressBackendNotFound:
		return ruleSpec{"Ingress backend service is missing", "The ingress references a service or port that is not present in the target namespace.", "Create or rename the backend through GitOps and verify controller status.", ActionGitOpsPR, "ingress", "describe"}
	case scanner.CategoryIngressClassMissing:
		return manual("Ingress has no claimable class", "No ingress class or legacy class annotation identifies the controller that should reconcile this ingress.", "Set the intended ingress class in the source manifest.", "ingress")
	case scanner.CategoryIngressPortInvalid:
		return manual("Ingress backend port is invalid", "The ingress backend selects a service port that is not exposed by the referenced service.", "Correct the backend service port in the source manifest.", "ingress")
	case scanner.CategoryIngressTLSSecretMissing:
		return manual("Ingress TLS secret is missing", "The ingress references a TLS secret that is absent or not yet provisioned.", "Inspect certificate issuance and create the secret through the configured certificate workflow.", "ingress")
	case scanner.CategoryNetworkPolicyOrphaned:
		return manual("NetworkPolicy selects no workload", "The policy selector does not match a current pod, so its intended traffic boundary is not enforced.", "Update or remove the policy through GitOps after confirming the intended workload labels.", "networkpolicy")
	case scanner.CategoryNetworkPolicyWide:
		return manual("NetworkPolicy selector is overly broad", "The policy selects a wider set of pods or namespaces than its declared security intent.", "Narrow the selector and review allowed ingress and egress peers through GitOps.", "networkpolicy")
	case scanner.CategoryNodePressure:
		return ruleSpec{"Node is under pressure", "The node reports resource pressure that can evict pods or prevent safe scheduling.", "Cordon the node while capacity and the pressure source are investigated.", ActionCordonNode, "node", "cordon"}
	case scanner.CategoryNodeNotReady:
		return ruleSpec{"Node is not ready", "The node controller reports a condition preventing reliable workload scheduling.", "Cordon the node while kubelet, runtime, and network health are investigated.", ActionCordonNode, "node", "cordon"}
	case scanner.CategoryNodeNetworkUnavailable:
		return ruleSpec{"Node network is unavailable", "The node reports that its network is unavailable to scheduled workloads.", "Cordon the node and inspect the CNI and node network conditions.", ActionCordonNode, "node", "cordon"}
	case scanner.CategoryNodeUnschedulable:
		return ruleSpec{"Node is unschedulable", "The node is marked unschedulable, so new pods cannot be placed there.", "Confirm the maintenance intent and uncordon only after node health is verified.", ActionCordonNode, "node", "cordon"}
	case scanner.CategoryNodeTaint:
		return ruleSpec{"Node taint affects scheduling", "A taint prevents workloads without a matching toleration from using the node.", "Review the taint intent and workload tolerations before changing scheduling policy.", ActionCordonNode, "node", "cordon"}
	case scanner.CategoryPVCPending:
		return ruleSpec{"PersistentVolumeClaim is pending", "The claim has not been bound to a volume or dynamically provisioned.", "Verify the storage class, CSI provisioner, quota, and requested capacity.", ActionManual, "pvc", "describe"}
	case scanner.CategoryPVLost:
		return ruleSpec{"PersistentVolume is lost", "The claim's bound volume is no longer available to the cluster.", "Inspect storage provider state and recovery options before recreating or deleting the claim.", ActionManual, "pvc", "describe"}
	case scanner.CategoryPVCStorageClassMissing:
		return ruleSpec{"PVC storage class is missing", "The claim requests a storage class that is not installed or cannot be resolved.", "Install or select the intended storage class through the cluster and workload configuration.", ActionManual, "pvc", "describe"}
	case scanner.CategoryPVSmallCapacity:
		return manual("Persistent volume capacity is insufficient", "The available volume capacity is below the workload's requested or expected size.", "Review the storage class and expand or replace the volume through the storage workflow.", "pv")
	case scanner.CategoryPVReleased:
		return manual("Persistent volume was released", "The volume is no longer bound but still retains a previous claim reference.", "Follow the storage retention policy before reusing or recycling the volume.", "pv")
	case scanner.CategoryPVFailed:
		return manual("Persistent volume provisioning failed", "The volume controller marked the volume as failed or unusable.", "Inspect CSI events and provider state before retrying provisioning.", "pv")
	case scanner.CategoryStorageClassDefault:
		return manual("Multiple default storage classes exist", "More than one storage class is marked as default, making implicit PVC provisioning ambiguous.", "Keep one intentional default and remove the conflicting annotation through cluster configuration.", "storageclass")
	case scanner.CategoryStorageClassDeprecated:
		return manual("Storage class is deprecated", "The selected storage class uses a deprecated or unsupported provisioning path.", "Migrate claims to the supported storage class through the storage workflow.", "storageclass")
	case scanner.CategoryStorageClassNoProvisioner:
		return manual("Storage class has no provisioner", "The storage class cannot provision volumes because no provisioner is configured.", "Set the supported CSI provisioner or select a valid storage class.", "storageclass")
	case scanner.CategoryHPAScalingLimited:
		return manual("HPA scaling is limited", "The horizontal pod autoscaler reached a configured scaling boundary.", "Review target utilization and min/max replica policy before changing capacity.", "hpa")
	case scanner.CategoryHPAMetricsUnavailable:
		return manual("HPA metrics are unavailable", "The autoscaler cannot obtain the metrics required to calculate a desired replica count.", "Verify metrics-server or the configured metrics adapter and its permissions.", "hpa")
	case scanner.CategoryHPATargetMissing:
		return manual("HPA target is missing", "The autoscaler references a workload target that cannot be resolved.", "Correct the scale target reference in the autoscaler manifest.", "hpa")
	case scanner.CategoryHPAMetricInvalid:
		return manual("HPA metric is invalid", "One or more autoscaler metric specifications cannot be evaluated.", "Correct the metric source and target type through the autoscaler configuration.", "hpa")
	case scanner.CategoryPDBDisruptionsBlocked:
		return manual("Pod disruption budget blocks disruption", "The budget has no available disruption allowance for the selected pods.", "Allow unhealthy pods to recover before draining or upgrading the node.", "pdb")
	case scanner.CategoryPDBSelectorInvalid:
		return manual("Pod disruption budget selector is invalid", "The PDB selector cannot express a valid set of protected pods.", "Correct the selector and verify the intended availability policy.", "pdb")
	case scanner.CategoryPDBNoMatchingPods:
		return manual("Pod disruption budget selects no pods", "The PDB selector does not match a current workload, so its protection intent is ineffective.", "Align the PDB selector with the workload labels through GitOps.", "pdb")
	case scanner.CategoryConfigMapEmpty:
		return manual("ConfigMap is empty", "The ConfigMap contains no usable data for its consumers.", "Populate or remove the ConfigMap through the owning configuration source.", "configmap")
	case scanner.CategoryConfigMapUnused:
		return manual("ConfigMap is unused", "No current workload reference was found for the ConfigMap.", "Confirm ownership and remove stale configuration only through the source repository.", "configmap")
	case scanner.CategoryConfigMapTooLarge:
		return manual("ConfigMap exceeds the safe size", "The ConfigMap is larger than the supported Kubernetes object size budget.", "Split or externalize the configuration through the deployment workflow.", "configmap")
	case scanner.CategoryWebhookServiceMissing:
		return manual("Admission webhook service is missing", "The webhook configuration points to a service that cannot be resolved.", "Restore the service or correct the webhook reference through its owning deployment.", "mutatingwebhookconfiguration")
	case scanner.CategoryWebhookNoActivePods:
		return manual("Admission webhook has no active pods", "The webhook service has no ready backend pods to receive admission calls.", "Inspect the webhook deployment, endpoints, and readiness probes.", "mutatingwebhookconfiguration")
	case scanner.CategoryWebhookTargetMissing:
		return manual("Admission webhook target is invalid", "The webhook target service, port, URL, or CA configuration cannot be resolved.", "Correct the webhook target and certificate configuration through GitOps.", "mutatingwebhookconfiguration")
	case scanner.CategorySecurityPrivilege:
		return manual("Workload has excessive privilege", "The workload requests a privileged or otherwise high-risk security capability.", "Remove unnecessary privilege and validate the change through policy and GitOps review.", "pod")
	case scanner.CategorySecurityClusterBinding:
		return manual("Cluster-wide binding grants broad access", "A cluster role binding grants permissions that may exceed the workload's intended scope.", "Review the binding subject and role rules, then reduce access through the authorization source.", "clusterrolebinding")
	case scanner.CategoryEKSClusterHealth:
		return manual("Cluster health signal is degraded", "The cluster integration reported a control-plane or managed-node health anomaly.", "Inspect cluster and node health through the provider's read-only diagnostics.", "nodes")
	case scanner.CategoryWarningEvent:
		return manual("Warning event was observed", "The Kubernetes event stream contains a warning associated with this resource.", "Inspect the bounded event history and current resource status before acting.", "event")
	case scanner.CategoryGatewayClassNotAccepted:
		return manual("GatewayClass is not accepted", "The Gateway API controller has not accepted the GatewayClass implementation.", "Inspect controller status and class parameters before changing the gateway configuration.", "gatewayclass")
	case scanner.CategoryGatewayNotAccepted:
		return manual("Gateway is not accepted", "The Gateway controller has not accepted the gateway specification.", "Review gateway conditions, listeners, and controller events.", "gateway")
	case scanner.CategoryGatewayNotProgrammed:
		return manual("Gateway is not programmed", "The gateway has not reached a programmed ready state.", "Inspect listener status and controller reconciliation events.", "gateway")
	case scanner.CategoryGatewayListenerInvalid:
		return manual("Gateway listener is invalid", "One or more gateway listeners cannot be attached or configured as declared.", "Correct listener protocol, hostname, port, and attachment policy through GitOps.", "gateway")
	case scanner.CategoryGatewaySpecInvalid:
		return manual("Gateway specification is invalid", "The gateway specification contains an unsupported or malformed field combination.", "Validate the Gateway API object against the installed controller version.", "gateway")
	case scanner.CategoryHTTPRouteNoParent:
		return manual("HTTPRoute has no parent", "The route is not attached to any accepted gateway parent.", "Verify parent references, namespace policy, and gateway listener attachment.", "httproute")
	case scanner.CategoryHTTPRouteParentNotAccepted:
		return manual("HTTPRoute parent rejected the route", "The referenced gateway parent has not accepted the route attachment.", "Inspect parent conditions and correct the route or listener policy.", "httproute")
	case scanner.CategoryHTTPRouteRefsNotResolved:
		return manual("HTTPRoute references are unresolved", "A route reference cannot be resolved under the installed Gateway API policy.", "Correct referenced groups, kinds, namespaces, and ReferenceGrant permissions.", "httproute")
	case scanner.CategoryHTTPRouteBackendMissing:
		return manual("HTTPRoute backend is missing", "The route references a backend service or port that does not exist.", "Create or correct the backend through the owning application manifest.", "httproute")
	case scanner.CategoryHTTPRouteBackendInvalid:
		return manual("HTTPRoute backend is invalid", "The backend reference uses an unsupported group, kind, port, or namespace combination.", "Align the backend reference with the Gateway API controller contract.", "httproute")
	case scanner.CategoryReferenceGrantInvalid:
		return manual("ReferenceGrant is invalid", "The ReferenceGrant does not authorize the declared cross-namespace reference safely.", "Correct the grant's from/to selectors and review the trust boundary.", "referencegrant")
	case scanner.CategoryReferenceGrantMissing:
		return manual("ReferenceGrant is missing", "A cross-namespace route reference has no matching authorization grant.", "Add the narrowly scoped ReferenceGrant through the owning namespace configuration.", "referencegrant")
	case scanner.CategoryOLMResourceUnhealthy:
		return manual("OLM resource is unhealthy", "An Operator Lifecycle Manager resource reports a failed or incomplete condition.", "Inspect operator, subscription, install plan, and catalog status before retrying.", "resource")
	case scanner.CategoryIntegrationResourceUnhealthy:
		return manual("Integration resource is unhealthy", "An optional integration resource reports an unhealthy condition.", "Inspect the integration controller status and dependency conditions.", "resource")
	case scanner.CategoryDynamicMalformed:
		return manual("Dynamic resource is malformed", "The optional resource payload does not satisfy the discovered API shape.", "Validate the resource against the installed CRD schema before changing it.", "resource")
	default:
		return manual("Anomaly detected", "The scanner reported an issue category that has no specialized rule yet.", "Inspect the resource status and warning events, then use the owning configuration workflow for remediation.", "resource")
	}
}

func (p *RuleBasedProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error) {
	if issue == nil {
		return nil, fmt.Errorf("issue is required")
	}
	if err := checkProviderContext(ctx); err != nil {
		return nil, classifyContextProviderError(err, p.Name(), "diagnose", normalizeContext(ctx))
	}
	redactor := p.redactor
	if redactor == nil {
		redactor = sanitizer.NewRedactor()
	}
	issue = scanner.SanitizeIssueWithRedactor(issue, redactor).AsIssue()
	if issue.ID == "" {
		issue.ID = fmt.Sprintf("%s/%s/%s", issue.Category, issue.Namespace, issue.Name)
	}
	if issue.Kind == "" {
		issue.Kind = "resource"
	}
	if issue.Name == "" {
		issue.Name = "resource"
	}
	if issue.Severity == "" {
		issue.Severity = scanner.SeverityMedium
	}
	diag := &Diagnosis{
		IssueID:         issue.ID,
		ProviderName:    p.Name(),
		Severity:        issue.Severity,
		ConfidenceScore: 0.90,
	}
	spec := ruleSpecFor(issue.Category)
	kind := safeRuleToken(issue.Kind, "resource")
	name := safeRuleToken(issue.Name, "resource")
	namespace := safeRuleToken(issue.Namespace, "default")
	diag.Summary = fmt.Sprintf("%s for %s/%s", spec.summary, kind, name)
	diag.RootCause = spec.rootCause
	if strings.TrimSpace(issue.Details) != "" {
		diag.RootCause += " Evidence: " + issue.Details
	}
	diag.RemediationPlan = spec.remediation
	diag.ActionType = spec.action
	diag.ProposedCommand = ruleCommand(spec, name, namespace)
	diag = diag.SanitizedWithRedactor(redactor).AsDiagnosis()
	if err := validateDiagnosis(diag, issue.ID, redactor); err != nil {
		diag.ProposedCommand = "# Review the sanitized scanner evidence before remediation"
		diag = diag.SanitizedWithRedactor(redactor).AsDiagnosis()
	}

	return diag, nil
}

func safeRuleToken(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "..") || strings.Contains(value, "://") || strings.Contains(value, "@") {
		return fallback
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("._/-=:", character) {
			continue
		}
		return fallback
	}
	return value
}

func ruleCommand(spec ruleSpec, name, namespace string) string {
	if spec.commandStyle == "cordon" {
		return "kubectl cordon " + name
	}
	if spec.commandStyle != "describe" || spec.resource == "resource" {
		return "# Review the sanitized scanner evidence before remediation"
	}
	return fmt.Sprintf("kubectl describe %s %s -n %s", spec.resource, name, namespace)
}

func (p *RuleBasedProvider) Explain(_ context.Context, query string, issue *scanner.Issue) (string, error) {
	redactor := p.redactor
	if redactor == nil {
		redactor = sanitizer.NewRedactor()
	}
	query = redactor.SanitizeText(query)
	if issue != nil {
		issue = scanner.SanitizeIssueWithRedactor(issue, redactor).AsIssue()
	}
	if issue == nil {
		return fmt.Sprintf("I am the Kubebee SRE AI Assistant (Rule-Based Engine).\n\nYou asked: %q\n\nI actively monitor all cluster workloads, nodes, and networking components. If an LLM API key (Claude, OpenAI, DeepSeek) is supplied, I can run deep cognitive root-cause analysis on stack traces.", query), nil
	}

	return fmt.Sprintf("### SRE Diagnostic Report: %s/%s\n\n- **Category**: `%s`\n- **Summary**: %s\n- **Technical Diagnosis**: %s\n\n#### Recommended Troubleshooting Commands:\n```bash\nkubectl describe %s %s -n %s\nkubectl logs %s -n %s --tail=50\n```",
		issue.Kind, issue.Name, issue.Category, issue.Summary, issue.Details, issue.Kind, issue.Name, issue.Namespace, issue.Name, issue.Namespace), nil
}
