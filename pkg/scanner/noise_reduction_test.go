package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	coretypedv1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

func TestScanConfigMapsHonorsOptionalVolumeAndProjectedSources(t *testing.T) {
	optionalTrue := true
	optionalFalse := false

	client := fake.NewSimpleClientset(
		&corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "optional-present", Namespace: "monitoring"},
			Data:       map[string]string{"rule.yaml": "ok"},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "prometheus-monitoring-0", Namespace: "monitoring"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "prometheus"}},
				Volumes: []corev1.Volume{
					{
						Name: "rulefiles-1",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: "prometheus-monitoring-prometheus-rulefiles-1"},
								Optional:             &optionalTrue,
							},
						},
					},
					{
						Name: "optional-present-vol",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: "optional-present"},
								Optional:             &optionalTrue,
							},
						},
					},
					{
						Name: "required-nil-vol",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: "required-nil"},
							},
						},
					},
					{
						Name: "required-false-vol",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: "required-false"},
								Optional:             &optionalFalse,
							},
						},
					},
					{
						Name: "projected-rules",
						VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								Sources: []corev1.VolumeProjection{
									{
										ConfigMap: &corev1.ConfigMapProjection{
											LocalObjectReference: corev1.LocalObjectReference{Name: "projected-optional"},
											Optional:             &optionalTrue,
										},
									},
									{
										ConfigMap: &corev1.ConfigMapProjection{
											LocalObjectReference: corev1.LocalObjectReference{Name: "projected-required"},
										},
									},
								},
							},
						},
					},
					{
						Name: "mixed-optional",
						VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{
								LocalObjectReference: corev1.LocalObjectReference{Name: "mixed-cm"},
								Optional:             &optionalTrue,
							},
						},
					},
				},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "consumer", Namespace: "monitoring"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "app"}},
						Volumes: []corev1.Volume{{
							Name: "mixed-required",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{{
										ConfigMap: &corev1.ConfigMapProjection{
											LocalObjectReference: corev1.LocalObjectReference{Name: "mixed-cm"},
											Optional:             &optionalFalse,
										},
									}},
								},
							},
						}},
					},
				},
			},
		},
	)

	issues, err := NewClusterScanner(client).scanConfigMaps(context.Background(), "monitoring")
	if err != nil {
		t.Fatalf("scanConfigMaps() error = %v", err)
	}

	missing := make(map[string]bool)
	for _, issue := range issues {
		if issue.Category == CategoryConfigMapReferenceMissing {
			missing[issue.Name] = true
		}
		if issue.Category == CategoryConfigMapUnused && issue.Name == "optional-present" {
			t.Fatalf("optional ConfigMap volume mount should still mark existing ConfigMap as used: %#v", issue)
		}
	}

	for _, unexpected := range []string{"prometheus-monitoring-prometheus-rulefiles-1", "projected-optional"} {
		if missing[unexpected] {
			t.Errorf("optional ConfigMap %q triggered ConfigMapReferenceMissing: %#v", unexpected, issues)
		}
	}
	for _, want := range []string{"required-nil", "required-false", "projected-required", "mixed-cm"} {
		if !missing[want] {
			t.Errorf("required ConfigMap %q did not trigger ConfigMapReferenceMissing: %#v", want, issues)
		}
	}
}

func TestScanServicesSkipsSingleInstanceCNPGReplicaOnly(t *testing.T) {
	client := fake.NewSimpleClientset(
		// Single-instance CNPG cluster (1 primary pod + 1 succeeded initdb job pod)
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pg-single-1",
				Namespace: "db",
				Labels:    map[string]string{"cnpg.io/cluster": "pg-single", "role": "primary"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pg-single-1-initdb",
				Namespace: "db",
				Labels:    map[string]string{"cnpg.io/cluster": "pg-single", "cnpg.io/jobRole": "initdb"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodSucceeded},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "pg-single-ro", Namespace: "db"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"cnpg.io/cluster": "pg-single", "role": "replica"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "pg-single-ro-instancerole", Namespace: "db"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"cnpg.io/cluster": "pg-single", "cnpg.io/instanceRole": "replica"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "pg-single-rw", Namespace: "db"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"cnpg.io/cluster": "pg-single", "role": "primary"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "pg-single-r", Namespace: "db"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"cnpg.io/cluster": "pg-single"}},
		},
		// Multi-instance CNPG cluster (>= 2 pods): broken -ro MUST alert
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pg-ha-1",
				Namespace: "db",
				Labels:    map[string]string{"cnpg.io/cluster": "pg-ha", "role": "primary"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pg-ha-2",
				Namespace: "db",
				Labels:    map[string]string{"cnpg.io/cluster": "pg-ha", "role": "replica"},
			},
			Status: corev1.PodStatus{Phase: corev1.PodPending},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "pg-ha-ro", Namespace: "db"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"cnpg.io/cluster": "pg-ha", "role": "replica"}},
		},
		// Normal Service with 0 endpoints MUST alert
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "normal-svc", Namespace: "db"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "missing"}},
		},
	)

	issues, err := NewClusterScanner(client).scanServices(context.Background(), "db")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}

	if hasIssue(issues, "pg-single-ro", CategoryServiceNoEndpoint) {
		t.Fatalf("single-instance CNPG -ro Service should be skipped: %#v", issues)
	}
	if hasIssue(issues, "pg-single-ro-instancerole", CategoryServiceNoEndpoint) {
		t.Fatalf("single-instance CNPG -ro (instanceRole) Service should be skipped: %#v", issues)
	}
	for _, want := range []string{"pg-single-rw", "pg-single-r", "pg-ha-ro", "normal-svc"} {
		if !hasIssue(issues, want, CategoryServiceNoEndpoint) {
			t.Errorf("Service %q should emit ServiceNoEndpoints: %#v", want, issues)
		}
	}

	// A cluster whose Pods cannot be listed is not known to be single-instance,
	// so its replica Service alerts.
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("pods forbidden"))
	})
	issues, err = NewClusterScanner(client).scanServices(context.Background(), "db")
	if err != nil {
		t.Fatalf("scanServices() with forbidden Pod list error = %v", err)
	}
	if !hasIssue(issues, "pg-single-ro", CategoryServiceNoEndpoint) {
		t.Fatalf("CNPG -ro Service must alert when its cluster's Pods cannot be listed: %#v", issues)
	}
}

func TestScanServicesEnrichesNoEndpointsDetailsWithIngressAndSiblingContext(t *testing.T) {
	ready := true
	pathType := networkingv1.PathTypePrefix
	client := fake.NewSimpleClientset(
		// Case 1: Orphaned keycloak Service with active sibling keycloak-keycloak and Ingress only targeting keycloak-keycloak
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "keycloak",
				Namespace: "keycloak",
				Labels:    map[string]string{"svc-only": "true"},
			},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app.kubernetes.io/name": "keycloak"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "keycloak-keycloak", Namespace: "keycloak"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app.kubernetes.io/name": "keycloak-keycloak"}},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "keycloak-keycloak-1",
				Namespace: "keycloak",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "keycloak-keycloak"},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.42.6.180"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "keycloak-keycloak", Namespace: "keycloak"},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{{
								Path:     "/",
								PathType: &pathType,
								Backend: networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{Name: "keycloak-keycloak"},
								},
							}},
						},
					},
				}},
			},
		},
		// Case 2: Shared app.kubernetes.io/instance sibling + Ingress targeting broken Service
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "legacy-web",
				Namespace: "apps",
				Labels:    map[string]string{"app.kubernetes.io/instance": "storefront"},
			},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "legacy-web"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "storefront-gateway",
				Namespace: "apps",
				Labels:    map[string]string{"app.kubernetes.io/instance": "storefront"},
			},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "storefront"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy-webhook", Namespace: "apps"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "webhook"}},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "storefront-gateway-1",
				Namespace: "apps",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "storefront-gateway"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"10.42.1.10"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
				{Addresses: []string{"10.42.1.11"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "legacy-webhook-1",
				Namespace: "apps",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "legacy-webhook"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"10.42.1.20"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "storefront-ing", Namespace: "apps"},
			Spec: networkingv1.IngressSpec{
				DefaultBackend: &networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{Name: "legacy-web"},
				},
			},
		},
	)

	scanner := NewClusterScanner(client)
	issues, err := scanner.scanServices(context.Background(), "")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}

	detailsBySvc := make(map[string]string)
	for _, issue := range issues {
		if issue.Category == CategoryServiceNoEndpoint {
			detailsBySvc[issue.Namespace+"/"+issue.Name] = issue.Details
		}
	}

	keycloakDetails := detailsBySvc["keycloak/keycloak"]
	if !strings.Contains(keycloakDetails, "no Ingress in namespace keycloak targets keycloak") {
		t.Errorf("keycloak Details missing no-Ingress note: %q", keycloakDetails)
	}
	if !strings.Contains(keycloakDetails, "keycloak-keycloak (1 ready)") {
		t.Errorf("keycloak Details missing active sibling keycloak-keycloak: %q", keycloakDetails)
	}
	if !strings.Contains(keycloakDetails, ServiceLikelyOrphanedMarker) || strings.Contains(keycloakDetails, ServiceRoutedByIngressMarker) {
		t.Errorf("unrouted keycloak Details must carry only the orphaned marker: %q", keycloakDetails)
	}

	appsDetails := detailsBySvc["apps/legacy-web"]
	if !strings.Contains(appsDetails, "targeted by Ingress(es) storefront-ing") {
		t.Errorf("legacy-web Details missing targeting Ingress: %q", appsDetails)
	}
	if !strings.Contains(appsDetails, ServiceRoutedByIngressMarker) || strings.Contains(appsDetails, ServiceLikelyOrphanedMarker) {
		t.Errorf("routed legacy-web Details must carry only the routed marker: %q", appsDetails)
	}
	if !strings.Contains(appsDetails, "storefront-gateway (2 ready)") {
		t.Errorf("legacy-web Details missing instance-label sibling storefront-gateway: %q", appsDetails)
	}
	if strings.Contains(appsDetails, "legacy-webhook") {
		t.Errorf("legacy-web Details falsely matched non-hyphen sibling legacy-webhook: %q", appsDetails)
	}

	// Verify sibling & ingress discovery clear scanplan filters during dependency lookups.
	client.ClearActions()
	plan := scanplan.Default()
	plan.IncludeNamespaces = []string{"keycloak"}
	plan.Names = []string{"keycloak"}
	plan.LabelSelector = "svc-only=true"
	plan.Analyzers = []string{"ServiceAnalyzer"}
	scopedReport, err := scanner.ScanWithPlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("scoped ScanWithPlan() error = %v", err)
	}
	if len(scopedReport.Issues) != 1 || !strings.Contains(scopedReport.Issues[0].Details, "keycloak-keycloak (1 ready)") {
		t.Fatalf("scoped ScanWithPlan() lost sibling context: %#v", scopedReport.Issues)
	}
	var sawUnfilteredIngressList, sawUnfilteredSiblingSvcList bool
	for _, action := range client.Actions() {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			continue
		}
		restrictions := listAction.GetListRestrictions()
		if action.GetResource().Resource == "ingresses" && restrictions.Fields.String() == "" && restrictions.Labels.String() == "" {
			sawUnfilteredIngressList = true
		}
		if action.GetResource().Resource == "services" && restrictions.Fields.String() == "" && restrictions.Labels.String() == "" {
			sawUnfilteredSiblingSvcList = true
		}
	}
	if !sawUnfilteredIngressList || !sawUnfilteredSiblingSvcList {
		t.Fatalf("expected unfiltered dependency lists (ingress=%t, services=%t)", sawUnfilteredIngressList, sawUnfilteredSiblingSvcList)
	}
}

func TestScanServicesDetailsReportsUnavailableLookupWithoutFalseNone(t *testing.T) {
	t.Run("sibling service list error", func(t *testing.T) {
		client := fake.NewSimpleClientset(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Labels: map[string]string{"team": "sre"}},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
		})
		calls := 0
		client.PrependReactor("list", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
			calls++
			if calls == 1 {
				return false, nil, nil
			}
			return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("services forbidden"))
		})

		plan := scanplan.Default()
		plan.IncludeNamespaces = []string{"default"}
		plan.LabelSelector = "team=sre"
		plan.Analyzers = []string{"ServiceAnalyzer"}
		report, err := NewClusterScanner(client).ScanWithPlan(context.Background(), plan)
		if err != nil {
			t.Fatalf("ScanWithPlan() error = %v", err)
		}
		if len(report.Issues) != 1 {
			t.Fatalf("expected 1 issue, got %#v", report.Issues)
		}
		details := report.Issues[0].Details
		if !strings.Contains(details, "Active sibling Service(s) with ready endpoints: lookup unavailable.") {
			t.Fatalf("expected sibling lookup unavailable message, got %q", details)
		}
		if strings.Contains(details, "Active sibling Service(s) with ready endpoints: none") {
			t.Fatalf("must not falsely report none when sibling list errored: %q", details)
		}
	})

	t.Run("ingress list error", func(t *testing.T) {
		client := fake.NewSimpleClientset(&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
		})
		client.PrependReactor("list", "ingresses", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("ingresses forbidden"))
		})

		issues, err := NewClusterScanner(client).scanServices(context.Background(), "default")
		if err != nil {
			t.Fatalf("scanServices() error = %v", err)
		}
		if len(issues) != 1 || !strings.Contains(issues[0].Details, "Ingress impact: lookup unavailable") {
			t.Fatalf("expected ingress lookup unavailable message, got %#v", issues)
		}
	})
}

func TestScanJobsSkipsSupersededCronJobFailuresAndKeepsActive(t *testing.T) {
	now := time.Now().UTC()
	controllerTrue := true
	controllerFalse := false
	backoff := int32(1)
	deadline := int64(60)
	overlappingDeadline := int64(5400) // 90m: StartTime(-2h) + 90m = -30m > LastSuccessfulTime(-1h)
	longUnreachedDeadline := int64(86400)

	lastSuccess := metav1.NewTime(now.Add(-1 * time.Hour))
	oldCreate := metav1.NewTime(now.Add(-4 * time.Hour))
	oldFail := metav1.NewTime(now.Add(-3 * time.Hour))
	oldStart := metav1.NewTime(now.Add(-2 * time.Hour))
	beforeSuccessFail := metav1.NewTime(now.Add(-90 * time.Minute))
	recentTime := metav1.NewTime(now.Add(-10 * time.Minute))

	cronOwner := func(name string, controller *bool) []metav1.OwnerReference {
		return []metav1.OwnerReference{{
			APIVersion: "batch/v1",
			Kind:       "CronJob",
			Name:       name,
			Controller: controller,
		}}
	}

	client := fake.NewSimpleClientset(
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-backup-offsite", Namespace: "velero"},
			Status:     batchv1.CronJobStatus{LastSuccessfulTime: &lastSuccess},
		},
		&batchv1.CronJob{
			ObjectMeta: metav1.ObjectMeta{Name: "never-succeeded", Namespace: "velero"},
		},
		// Superseded failed Job -> skip
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "cluster-backup-offsite-old-failed",
				Namespace:         "velero",
				Labels:            map[string]string{"job-only": "true"},
				CreationTimestamp: oldCreate,
				OwnerReferences:   cronOwner("cluster-backup-offsite", &controllerTrue),
			},
			Status: batchv1.JobStatus{
				Failed: 1,
				Conditions: []batchv1.JobCondition{{
					Type:               batchv1.JobFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "BackoffLimitExceeded",
					LastTransitionTime: oldFail,
				}},
			},
		},
		// Superseded backoff + deadline Job -> skip all 3 categories
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "cluster-backup-offsite-old-deadline",
				Namespace:         "velero",
				CreationTimestamp: oldCreate,
				OwnerReferences:   cronOwner("cluster-backup-offsite", &controllerTrue),
			},
			Spec: batchv1.JobSpec{
				BackoffLimit:          &backoff,
				ActiveDeadlineSeconds: &deadline,
			},
			Status: batchv1.JobStatus{
				StartTime: &oldStart,
				Failed:    2,
			},
		},
		// Started before LastSuccessfulTime, but failed via BackoffLimitExceeded BEFORE LastSuccessfulTime
		// with an unreached 24h ActiveDeadlineSeconds -> still superseded and skipped
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "cluster-backup-offsite-unreached-deadline",
				Namespace:         "velero",
				CreationTimestamp: oldCreate,
				OwnerReferences:   cronOwner("cluster-backup-offsite", &controllerTrue),
			},
			Spec: batchv1.JobSpec{
				ActiveDeadlineSeconds: &longUnreachedDeadline,
			},
			Status: batchv1.JobStatus{
				StartTime: &oldStart,
				Failed:    1,
				Conditions: []batchv1.JobCondition{{
					Type:               batchv1.JobFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "BackoffLimitExceeded",
					LastTransitionTime: beforeSuccessFail,
				}},
			},
		},
		// Started before LastSuccessfulTime, but ActiveDeadlineSeconds expired AFTER LastSuccessfulTime -> MUST keep
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "cluster-backup-offsite-overlapping-deadline",
				Namespace:         "velero",
				CreationTimestamp: oldCreate,
				OwnerReferences:   cronOwner("cluster-backup-offsite", &controllerTrue),
			},
			Spec: batchv1.JobSpec{
				ActiveDeadlineSeconds: &overlappingDeadline,
			},
			Status: batchv1.JobStatus{
				StartTime: &oldStart,
			},
		},
		// Failed AFTER LastSuccessfulTime -> MUST keep
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "cluster-backup-offsite-recent",
				Namespace:         "velero",
				CreationTimestamp: recentTime,
				OwnerReferences:   cronOwner("cluster-backup-offsite", &controllerTrue),
			},
			Status: batchv1.JobStatus{
				Failed: 1,
				Conditions: []batchv1.JobCondition{{
					Type:               batchv1.JobFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "BackoffLimitExceeded",
					LastTransitionTime: recentTime,
				}},
			},
		},
		// Created before LastSuccessfulTime, transitioned to Failed AFTER LastSuccessfulTime -> MUST keep
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "cluster-backup-offsite-late-fail",
				Namespace:         "velero",
				CreationTimestamp: oldCreate,
				OwnerReferences:   cronOwner("cluster-backup-offsite", &controllerTrue),
			},
			Status: batchv1.JobStatus{
				Failed: 1,
				Conditions: []batchv1.JobCondition{{
					Type:               batchv1.JobFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "DeadlineExceeded",
					LastTransitionTime: recentTime,
				}},
			},
		},
		// Equal timestamp (not strictly after) -> MUST keep
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "cluster-backup-offsite-equal",
				Namespace:         "velero",
				CreationTimestamp: lastSuccess,
				OwnerReferences:   cronOwner("cluster-backup-offsite", &controllerTrue),
			},
			Status: batchv1.JobStatus{
				Failed: 1,
				Conditions: []batchv1.JobCondition{{
					Type:               batchv1.JobFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "BackoffLimitExceeded",
					LastTransitionTime: lastSuccess,
				}},
			},
		},
		// Owning CronJob has nil LastSuccessfulTime -> MUST keep
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "never-succeeded-1",
				Namespace:         "velero",
				CreationTimestamp: oldCreate,
				OwnerReferences:   cronOwner("never-succeeded", &controllerTrue),
			},
			Status: batchv1.JobStatus{
				Failed: 1,
				Conditions: []batchv1.JobCondition{{
					Type:               batchv1.JobFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "BackoffLimitExceeded",
					LastTransitionTime: oldFail,
				}},
			},
		},
		// Non-controller OwnerReference -> MUST keep
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "non-controller-owner",
				Namespace:         "velero",
				CreationTimestamp: oldCreate,
				OwnerReferences:   cronOwner("cluster-backup-offsite", &controllerFalse),
			},
			Status: batchv1.JobStatus{
				Failed: 1,
				Conditions: []batchv1.JobCondition{{
					Type:               batchv1.JobFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "BackoffLimitExceeded",
					LastTransitionTime: oldFail,
				}},
			},
		},
		// Standalone Job (no OwnerRef) -> MUST keep
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "pg-db-init",
				Namespace:         "velero",
				CreationTimestamp: oldCreate,
			},
			Status: batchv1.JobStatus{
				Failed: 1,
				Conditions: []batchv1.JobCondition{{
					Type:               batchv1.JobFailed,
					Status:             corev1.ConditionTrue,
					Reason:             "BackoffLimitExceeded",
					LastTransitionTime: oldFail,
				}},
			},
		},
	)

	scanner := NewClusterScanner(client)
	issues, err := scanner.scanJobs(context.Background(), "velero")
	if err != nil {
		t.Fatalf("scanJobs() error = %v", err)
	}
	cronJobLists := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "list" && action.GetResource().Resource == "cronjobs" {
			cronJobLists++
		}
	}
	if cronJobLists != 1 {
		t.Fatalf("scanJobs() listed CronJobs %d times for several owned failed Jobs, want 1", cronJobLists)
	}

	for _, skipped := range []string{"cluster-backup-offsite-old-failed", "cluster-backup-offsite-old-deadline", "cluster-backup-offsite-unreached-deadline"} {
		for _, issue := range issues {
			if issue.Name == skipped {
				t.Fatalf("superseded CronJob job %q should be skipped, got %#v", skipped, issue)
			}
		}
	}
	if !hasIssue(issues, "cluster-backup-offsite-overlapping-deadline", CategoryJobDeadlineExceeded) {
		t.Errorf("expected JobDeadlineExceeded for overlapping deadline breached after LastSuccessfulTime: %#v", issues)
	}
	for _, want := range []string{
		"cluster-backup-offsite-recent",
		"cluster-backup-offsite-late-fail",
		"cluster-backup-offsite-equal",
		"never-succeeded-1",
		"non-controller-owner",
		"pg-db-init",
	} {
		if !hasIssue(issues, want, CategoryJobFailed) {
			t.Errorf("expected JobFailed issue for %q: %#v", want, issues)
		}
	}

	// Verify single-job scanplan still looks up the owning CronJob unfiltered and skips superseded failure.
	client.ClearActions()
	plan := scanplan.Default()
	plan.IncludeNamespaces = []string{"velero"}
	plan.Names = []string{"cluster-backup-offsite-old-failed"}
	plan.LabelSelector = "job-only=true"
	plan.Analyzers = []string{"JobAnalyzer"}
	scopedReport, err := scanner.ScanWithPlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("scoped ScanWithPlan() error = %v", err)
	}
	if len(scopedReport.Issues) != 0 {
		t.Fatalf("scoped ScanWithPlan() should skip superseded CronJob job, got %#v", scopedReport.Issues)
	}
	sawUnfilteredCronJobList := false
	for _, action := range client.Actions() {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			continue
		}
		if action.GetResource().Resource == "cronjobs" {
			restrictions := listAction.GetListRestrictions()
			if restrictions.Fields.String() == "" && restrictions.Labels.String() == "" {
				sawUnfilteredCronJobList = true
			}
		}
	}
	if !sawUnfilteredCronJobList {
		t.Fatalf("expected unfiltered cronjobs dependency list under scoped JobAnalyzer plan")
	}

	// Without the CronJob's status a failure cannot be shown to be superseded:
	// it is reported, and the analyzer run is marked incomplete.
	client.PrependReactor("list", "cronjobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("cronjobs forbidden"))
	})
	issues, err = scanner.scanJobs(context.Background(), "velero")
	if !apierrors.IsForbidden(err) {
		t.Fatalf("scanJobs() with forbidden CronJob list error = %v, want Forbidden", err)
	}
	if !hasIssue(issues, "cluster-backup-offsite-old-failed", CategoryJobFailed) {
		t.Fatalf("failed Job must be reported when its CronJob cannot be read: %#v", issues)
	}
}

func TestScanJobsDoesNotListCronJobsWithoutOwnedFailures(t *testing.T) {
	controller := true
	failed := []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
	client := fake.NewSimpleClientset(
		// A failed Job that no CronJob controls.
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{Name: "standalone", Namespace: "default"},
			Status:     batchv1.JobStatus{Failed: 1, Conditions: failed},
		},
		// A CronJob-owned Job with nothing to report.
		&batchv1.Job{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "nightly-1",
				Namespace:       "default",
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "CronJob", Name: "nightly", Controller: &controller}},
			},
			Status: batchv1.JobStatus{Succeeded: 1, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}},
		},
	)

	issues, err := NewClusterScanner(client).scanJobs(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanJobs() error = %v", err)
	}
	if len(issues) != 1 || !hasIssue(issues, "standalone", CategoryJobFailed) {
		t.Fatalf("scanJobs() = %#v, want only the standalone JobFailed finding", issues)
	}
	for _, action := range client.Actions() {
		if action.GetResource().Resource == "cronjobs" {
			t.Fatalf("scanJobs() listed CronJobs although no failing Job is owned by one: %#v", action)
		}
	}
}

type optionAwareLogClient struct {
	kubernetes.Interface
	base       *url.URL
	httpClient *http.Client
}

func (c optionAwareLogClient) CoreV1() coretypedv1.CoreV1Interface {
	return optionAwareLogCore{CoreV1Interface: c.Interface.CoreV1(), base: c.base, httpClient: c.httpClient}
}

type optionAwareLogCore struct {
	coretypedv1.CoreV1Interface
	base       *url.URL
	httpClient *http.Client
}

func (c optionAwareLogCore) Pods(namespace string) coretypedv1.PodInterface {
	return optionAwareLogPods{PodInterface: c.CoreV1Interface.Pods(namespace), base: c.base, httpClient: c.httpClient}
}

type optionAwareLogPods struct {
	coretypedv1.PodInterface
	base       *url.URL
	httpClient *http.Client
}

func (p optionAwareLogPods) GetLogs(name string, opts *corev1.PodLogOptions) *rest.Request {
	req := rest.NewRequestWithClient(p.base, "", rest.ClientContentConfig{}, p.httpClient).Resource("pods").Name(name).SubResource("log")
	if opts != nil {
		req.Param("container", opts.Container)
		req.Param("previous", strconv.FormatBool(opts.Previous))
		if opts.SinceSeconds != nil {
			req.Param("sinceSeconds", strconv.FormatInt(*opts.SinceSeconds, 10))
		}
	}
	return req
}

func TestScanPodLogsDowngradesOnlyStaleReadyPreviousErrors(t *testing.T) {
	now := time.Now().UTC()
	staleFinished := metav1.NewTime(now.Add(-48 * time.Hour))
	recentFinished := metav1.NewTime(now.Add(-6 * time.Hour))

	makePod := func(name string, ready bool, waiting bool, finished *metav1.Time) *corev1.Pod {
		state := corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(now)}}
		if waiting {
			state = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
		}
		var lastTerm *corev1.ContainerStateTerminated
		if finished != nil {
			lastTerm = &corev1.ContainerStateTerminated{FinishedAt: *finished, ExitCode: 1}
		}
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "apps"},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{{
					Name:                 "app",
					Ready:                ready,
					RestartCount:         2,
					State:                state,
					LastTerminationState: corev1.ContainerState{Terminated: lastTerm},
				}},
			},
		}
	}

	staleReady := makePod("stale-ready", true, false, &staleFinished)
	staleActiveErr := makePod("stale-active-err", true, false, &staleFinished)
	recentReady := makePod("recent-ready", true, false, &recentFinished)
	staleUnready := makePod("stale-unready", false, true, &staleFinished)
	staleZeroFinished := makePod("stale-zero-finished", true, false, &metav1.Time{})

	base, _ := url.Parse("http://logs.invalid")
	client := optionAwareLogClient{
		Interface: fake.NewSimpleClientset(staleReady, staleActiveErr, recentReady, staleUnready, staleZeroFinished),
		base:      base,
		httpClient: &http.Client{Transport: coverageRoundTripper(func(r *http.Request) (*http.Response, error) {
			previous := r.URL.Query().Get("previous") == "true"
			path := r.URL.Path
			body := "all healthy\n"
			switch {
			case strings.Contains(path, "/stale-ready/") && previous:
				body = "panic: historical crash months ago\n"
			case strings.Contains(path, "/stale-active-err/") && !previous:
				body = "fatal: active container crash loop\n"
			case strings.Contains(path, "/recent-ready/") && previous:
				body = "panic: recent crash\n"
			case strings.Contains(path, "/stale-unready/") && previous:
				body = "panic: still unready\n"
			case strings.Contains(path, "/stale-zero-finished/") && previous:
				body = "panic: unknown termination time\n"
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &coverageStringBody{strings.NewReader(body)}}, nil
		})},
	}

	issues, err := NewClusterScanner(client).scanPodLogs(context.Background(), "apps")
	if err != nil {
		t.Fatalf("scanPodLogs() error = %v", err)
	}

	sevByPod := make(map[string]Severity, len(issues))
	for _, issue := range issues {
		if issue.Category == CategoryPodLogError {
			sevByPod[issue.Name] = issue.Severity
		}
	}
	if len(sevByPod) != 5 {
		t.Fatalf("expected 5 PodLogError issues, got %d: %#v", len(sevByPod), issues)
	}
	if sevByPod["stale-ready"] != SeverityMedium {
		t.Errorf("stale-ready previous PodLogError severity = %q, want MEDIUM", sevByPod["stale-ready"])
	}
	for _, wantHigh := range []string{"stale-active-err", "recent-ready", "stale-unready", "stale-zero-finished"} {
		if sevByPod[wantHigh] != SeverityHigh {
			t.Errorf("%s PodLogError severity = %q, want HIGH", wantHigh, sevByPod[wantHigh])
		}
	}
}

func TestHighRestartFallsBackToRunningStartedAtWhenLastTerminatedMissing(t *testing.T) {
	now := time.Now().UTC()
	staleRunning := corev1.ContainerStatus{
		Name:         "kube-vip",
		Ready:        true,
		RestartCount: 25,
		State: corev1.ContainerState{
			Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(now.Add(-8 * 24 * time.Hour))},
		},
		LastTerminationState: corev1.ContainerState{
			Waiting: &corev1.ContainerStateWaiting{},
		},
	}
	if got := classifyHighRestartSeverity(staleRunning, now); got != SeverityMedium {
		t.Fatalf("stale running container with empty LastTerminationState.Terminated = %q, want MEDIUM", got)
	}

	recentRunning := staleRunning
	recentRunning.State.Running = &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(now.Add(-2 * time.Hour))}
	if got := classifyHighRestartSeverity(recentRunning, now); got != SeverityHigh {
		t.Fatalf("recently restarted container = %q, want HIGH", got)
	}
}

func TestScanPodLogsCurrentUsesSinceSecondsEvenWithRestarts(t *testing.T) {
	now := time.Now().UTC()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "longhorn-csi-plugin-test", Namespace: "longhorn-system"},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name:         "longhorn-liveness-probe",
				Ready:        true,
				RestartCount: 7,
				State: corev1.ContainerState{
					Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(now.Add(-30 * 24 * time.Hour))},
				},
			}},
		},
	}
	var currentSinceSeconds string
	base, _ := url.Parse("http://logs.invalid")
	client := optionAwareLogClient{
		Interface: fake.NewSimpleClientset(pod),
		base:      base,
		httpClient: &http.Client{Transport: coverageRoundTripper(func(r *http.Request) (*http.Response, error) {
			if r.URL.Query().Get("previous") != "true" {
				currentSinceSeconds = r.URL.Query().Get("sinceSeconds")
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: &coverageStringBody{strings.NewReader("all healthy\n")}}, nil
		})},
	}
	if _, err := NewClusterScanner(client).scanPodLogs(context.Background(), "longhorn-system"); err != nil {
		t.Fatalf("scanPodLogs() error = %v", err)
	}
	if currentSinceSeconds == "" || currentSinceSeconds == "0" {
		t.Fatalf("expected non-zero sinceSeconds on current container logs with RestartCount>0, got %q", currentSinceSeconds)
	}
}
