package scanner

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

func TestScanServicesCountsReadyEndpointSlices(t *testing.T) {
	ready := true
	notReady := false
	client := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": "web"},
				Ports:    []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt(8080)}},
			},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-1",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "web"},
			},
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
				{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &notReady}},
				{Addresses: []string{"10.0.0.3"}},
			},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-1",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "other"},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.4"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		},
	)

	issues, err := NewClusterScanner(client).scanServices(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}
	for _, issue := range issues {
		if issue.Category == CategoryServiceNoEndpoint {
			t.Fatalf("scanServices() reported no endpoints despite ready EndpointSlice endpoint: %#v", issues)
		}
	}
}

func TestScanServicesIgnoresEndpointSlicesForOtherServices(t *testing.T) {
	ready := true
	client := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-1",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "other"},
			},
			Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		},
	)

	issues, err := NewClusterScanner(client).scanServices(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}
	if !hasIssue(issues, "web", CategoryServiceNoEndpoint) {
		t.Fatalf("scanServices() counted an EndpointSlice belonging to another Service: %#v", issues)
	}
}

func TestScanServicesFallsBackToLegacyEndpoints(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
		},
		&corev1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Subsets:    []corev1.EndpointSubset{{Addresses: []corev1.EndpointAddress{{IP: "10.0.0.1"}}}},
		},
	)

	issues, err := NewClusterScanner(client).scanServices(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}
	if hasIssue(issues, "web", CategoryServiceNoEndpoint) {
		t.Fatalf("scanServices() ignored a ready legacy Endpoints object: %#v", issues)
	}
}

func TestScanNetworkPoliciesHonorsExpressionsAndEmptySelectors(t *testing.T) {
	client := fake.NewSimpleClientset(
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "expression", Namespace: "default"},
			Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"backend"}}},
			}},
		},
		&networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "default"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default", Labels: map[string]string{"tier": "backend"}}},
	)

	issues, err := NewClusterScanner(client).scanNetworkPolicies(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanNetworkPolicies() error = %v", err)
	}
	for _, issue := range issues {
		if issue.Name == "expression" && issue.Category == CategoryNetworkPolicyOrphaned {
			t.Fatalf("expression selector was treated as unmatched: %#v", issues)
		}
	}
	if !hasIssue(issues, "empty", CategoryNetworkPolicyWide) {
		t.Fatalf("empty podSelector did not produce wide-selector finding: %#v", issues)
	}
}

func TestScanNetworkPoliciesDoesNotApplyPolicyNameSelectorToPods(t *testing.T) {
	plan := scanplan.Default()
	plan.Names = []string{"backend-policy"}
	ctx := scanplan.WithContext(context.Background(), plan)
	client := fake.NewSimpleClientset(
		&networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "backend-policy", Namespace: "default"},
			Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}}},
		},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "backend-pod", Namespace: "default", Labels: map[string]string{"app": "backend"}}},
	)

	issues, err := NewClusterScanner(client).scanNetworkPolicies(ctx, "default")
	if err != nil {
		t.Fatalf("scanNetworkPolicies() error = %v", err)
	}
	if hasIssue(issues, "backend-policy", CategoryNetworkPolicyOrphaned) {
		t.Fatalf("policy name field selector leaked into dependent pod list: %#v", issues)
	}
}

func TestNetworkPolicyPodListOptionsComposesNativeSelectors(t *testing.T) {
	plan := scanplan.Default()
	plan.LabelSelector = "team=sre"
	plan.Names = []string{"backend-policy"}
	ctx := scanplan.WithContext(context.Background(), plan)
	policySelector, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"backend"}}},
	})
	if err != nil {
		t.Fatalf("LabelSelectorAsSelector() error = %v", err)
	}

	options, err := networkPolicyPodListOptions(ctx, policySelector)
	if err != nil {
		t.Fatalf("networkPolicyPodListOptions() error = %v", err)
	}
	if options.FieldSelector != "" {
		t.Fatalf("dependent pod field selector = %q, want empty", options.FieldSelector)
	}
	combined, err := labels.Parse(options.LabelSelector)
	if err != nil {
		t.Fatalf("combined label selector %q is invalid: %v", options.LabelSelector, err)
	}
	if !combined.Matches(labels.Set{"team": "sre", "tier": "backend"}) {
		t.Fatalf("combined selector %q does not match the intended pod", options.LabelSelector)
	}
	if combined.Matches(labels.Set{"team": "sre", "tier": "frontend"}) {
		t.Fatalf("combined selector %q matched a pod outside MatchExpressions", options.LabelSelector)
	}
	if combined.Matches(labels.Set{"team": "other", "tier": "backend"}) {
		t.Fatalf("combined selector %q ignored the scan-plan label selector", options.LabelSelector)
	}
	if networkPolicySelectorIsEmpty(metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpExists}}}) {
		t.Fatal("a MatchExpressions-only selector was treated as empty")
	}
}

func TestScanNetworkPoliciesPropagatesPodListErrors(t *testing.T) {
	client := fake.NewSimpleClientset(&networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "backend-policy", Namespace: "default"},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}}},
	})
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("pod access denied"))
	})

	_, err := NewClusterScanner(client).scanNetworkPolicies(context.Background(), "default")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanNetworkPolicies() error = %v, want Forbidden", err)
	}
}

func TestScanIngressesPropagatesServiceListErrors(t *testing.T) {
	client := fake.NewSimpleClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
	})
	client.PrependReactor("list", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("service access denied"))
	})

	_, err := NewClusterScanner(client).scanIngresses(context.Background(), "default")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanIngresses() error = %v, want Forbidden", err)
	}
}

func TestScanIngressesPropagatesSecretListErrors(t *testing.T) {
	client := fake.NewSimpleClientset(&networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       networkingv1.IngressSpec{TLS: []networkingv1.IngressTLS{{SecretName: "web-tls"}}},
	})
	client.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "", errors.New("secret access denied"))
	})

	_, err := NewClusterScanner(client).scanIngresses(context.Background(), "default")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanIngresses() error = %v, want Forbidden", err)
	}
}

func TestScanIngressesDoesNotApplyIngressNameSelectorToDependencies(t *testing.T) {
	plan := scanplan.Default()
	plan.Names = []string{"web-ingress"}
	ctx := scanplan.WithContext(context.Background(), plan)
	client := fake.NewSimpleClientset(
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "web-ingress", Namespace: "default", Annotations: map[string]string{"kubernetes.io/ingress.class": "nginx"}},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{{IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
					Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "backend", Port: networkingv1.ServiceBackendPort{Number: 80}}}}},
				}}}},
				TLS: []networkingv1.IngressTLS{{SecretName: "web-tls"}},
			},
		},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "web-tls", Namespace: "default"}},
	)
	var serviceFields, secretFields string
	client.PrependReactor("list", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			t.Fatalf("services action type = %T, want ListAction", action)
		}
		serviceFields = listAction.GetListRestrictions().Fields.String()
		return false, nil, nil
	})
	client.PrependReactor("list", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			t.Fatalf("secrets action type = %T, want ListAction", action)
		}
		secretFields = listAction.GetListRestrictions().Fields.String()
		return false, nil, nil
	})

	issues, err := NewClusterScanner(client).scanIngresses(ctx, "default")
	if err != nil {
		t.Fatalf("scanIngresses() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("scanIngresses() applied Ingress name selector to dependencies: %#v", issues)
	}
	if serviceFields != "" || secretFields != "" {
		t.Fatalf("scanIngresses() propagated dependent field selectors: services=%q secrets=%q", serviceFields, secretFields)
	}
}

func TestScanIngressSemanticsDoesNotApplyIngressNameSelectorToDependencies(t *testing.T) {
	plan := scanplan.Default()
	plan.Names = []string{"web-ingress"}
	ctx := scanplan.WithContext(context.Background(), plan)
	client := fake.NewSimpleClientset(
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "web-ingress", Namespace: "default", Annotations: map[string]string{"kubernetes.io/ingress.class": "nginx"}},
			Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "backend", Port: networkingv1.ServiceBackendPort{Number: 80}}}}},
			}}}}},
		},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: "default"}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 80}}}},
	)
	var serviceFields string
	client.PrependReactor("list", "services", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			t.Fatalf("services action type = %T, want ListAction", action)
		}
		serviceFields = listAction.GetListRestrictions().Fields.String()
		return false, nil, nil
	})

	issues, err := NewClusterScanner(client).scanIngressSemantics(ctx, "default")
	if err != nil {
		t.Fatalf("scanIngressSemantics() error = %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("scanIngressSemantics() applied Ingress name selector to dependencies: %#v", issues)
	}
	if serviceFields != "" {
		t.Fatalf("dependent Service field selector = %q, want empty", serviceFields)
	}
}

func TestScanStorageAppliesPlanOptionsToDirectClusterResources(t *testing.T) {
	plan := scanplan.Default()
	plan.LabelSelector = "storage-tier=gold"
	plan.Names = []string{"fast"}
	ctx := scanplan.WithContext(context.Background(), plan)
	client := fake.NewSimpleClientset()
	var classRestrictions, volumeRestrictions k8stesting.ListRestrictions
	client.PrependReactor("list", "storageclasses", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			t.Fatalf("StorageClass action type = %T, want ListAction", action)
		}
		classRestrictions = listAction.GetListRestrictions()
		return true, &storagev1.StorageClassList{}, nil
	})
	client.PrependReactor("list", "persistentvolumes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			t.Fatalf("PersistentVolume action type = %T, want ListAction", action)
		}
		volumeRestrictions = listAction.GetListRestrictions()
		return true, &corev1.PersistentVolumeList{}, nil
	})
	client.PrependReactor("list", "persistentvolumeclaims", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PersistentVolumeClaimList{}, nil
	})

	if _, err := NewClusterScanner(client).scanStorage(ctx, "default"); err != nil {
		t.Fatalf("scanStorage() error = %v", err)
	}
	if classRestrictions.Labels.String() != "storage-tier=gold" || classRestrictions.Fields.String() != "metadata.name=fast" {
		t.Fatalf("StorageClass list restrictions = labels=%q fields=%q, want plan options", classRestrictions.Labels.String(), classRestrictions.Fields.String())
	}
	if volumeRestrictions.Labels.String() != "storage-tier=gold" || volumeRestrictions.Fields.String() != "metadata.name=fast" {
		t.Fatalf("PersistentVolume list restrictions = labels=%q fields=%q, want plan options", volumeRestrictions.Labels.String(), volumeRestrictions.Fields.String())
	}
}

func TestScanSecurityResolvesClusterRolesThroughBindings(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "workload-reader"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}},
		},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "namespace-admin", Namespace: "default"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}}},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "workload-reader-binding"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "workload-reader"},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "namespace-admin-binding", Namespace: "default"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "namespace-admin"},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-role-binding", Namespace: "default"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "workload-reader"},
		},
	)

	issues, err := NewClusterScanner(client).scanSecurity(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanSecurity() error = %v", err)
	}
	if !hasIssue(issues, "workload-reader-binding", CategorySecurityClusterBinding) {
		t.Fatalf("ClusterRoleBinding wildcard permissions were not reported: %#v", issues)
	}
	if !hasIssue(issues, "cluster-role-binding", CategorySecurityClusterBinding) {
		t.Fatalf("RoleBinding to wildcard ClusterRole was not reported: %#v", issues)
	}
	if !hasIssue(issues, "namespace-admin-binding", CategorySecurityClusterBinding) {
		t.Fatalf("Role wildcard permissions were not reported: %#v", issues)
	}
}

func TestScanSecurityPropagatesRoleLookupPermissionErrors(t *testing.T) {
	client := fake.NewSimpleClientset(&rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "binding", Namespace: "default"},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "restricted"},
	})
	client.PrependReactor("get", "roles", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), "restricted", errors.New("role access denied"))
	})

	_, err := NewClusterScanner(client).scanSecurity(context.Background(), "default")
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("scanSecurity() error = %v, want Forbidden", err)
	}
}

func TestScanSecurityAppliesScanPlanToClusterRoleBindings(t *testing.T) {
	plan := scanplan.Default()
	plan.Names = []string{"selected-binding"}
	ctx := scanplan.WithContext(context.Background(), plan)
	client := fake.NewSimpleClientset()
	var fields string
	client.PrependReactor("list", "clusterrolebindings", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			t.Fatalf("ClusterRoleBinding action type = %T, want ListAction", action)
		}
		fields = listAction.GetListRestrictions().Fields.String()
		return false, nil, nil
	})

	if _, err := NewClusterScanner(client).scanSecurity(ctx, ""); err != nil {
		t.Fatalf("scanSecurity() error = %v", err)
	}
	if fields != "metadata.name=selected-binding" {
		t.Fatalf("ClusterRoleBinding list field selector = %q, want metadata.name=selected-binding", fields)
	}
}

func TestPodSecurityFindingsApplyPodRunAsUserToAllContainerClasses(t *testing.T) {
	root := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "rooted", Namespace: "default"},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsUser: &root},
			InitContainers:  []corev1.Container{{Name: "init"}},
			Containers:      []corev1.Container{{Name: "app"}},
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name: "debug",
			}}},
		},
	}

	issues := podSecurityFindings(pod)
	for _, name := range []string{"init", "app", "debug"} {
		if !hasIssueID(issues, makeID("default", "Pod", "rooted", "Root-"+containerSecurityID(name))) {
			t.Errorf("podSecurityFindings() omitted inherited root finding for %s: %#v", name, issues)
		}
	}
}

func hasIssue(issues []*Issue, name string, category IssueCategory) bool {
	for _, issue := range issues {
		if issue != nil && issue.Name == name && issue.Category == category {
			return true
		}
	}
	return false
}

func hasIssueID(issues []*Issue, id string) bool {
	for _, issue := range issues {
		if issue != nil && issue.ID == id {
			return true
		}
	}
	return false
}

func containerSecurityID(name string) string {
	if name == "debug" {
		return "ephemeral-" + name
	}
	return name
}
