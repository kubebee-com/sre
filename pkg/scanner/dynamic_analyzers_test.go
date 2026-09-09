package scanner

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	typedfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

func TestDynamicAnalyzerSetMetadataIsExplicit(t *testing.T) {
	set := NewDynamicAnalyzerSet(fake.NewSimpleDynamicClient(runtime.NewScheme()))
	if len(set.DynamicAnalyzers()) == 0 {
		t.Fatal("NewDynamicAnalyzerSet() returned no analyzers")
	}

	wanted := map[string]string{
		"GatewayClassAnalyzer":          "gateway-api",
		"GatewayAnalyzer":               "gateway-api",
		"HTTPRouteAnalyzer":             "gateway-api",
		"ReferenceGrantAnalyzer":        "gateway-api",
		"ClusterServiceVersionAnalyzer": "olm",
		"KEDAAnalyzer":                  "integration",
		"KyvernoAnalyzer":               "integration",
		"PrometheusOperatorAnalyzer":    "integration",
	}
	seen := make(map[string]bool)
	for _, analyzer := range set.DynamicAnalyzers() {
		info, ok := analyzer.(DynamicAnalyzer)
		if !ok {
			t.Fatalf("%T does not expose dynamic metadata", analyzer)
		}
		dynamicInfo := info.DynamicInfo()
		if dynamicInfo.Name == "" || dynamicInfo.Resource == "" || dynamicInfo.Description == "" || dynamicInfo.DocsURL == "" {
			t.Fatalf("incomplete analyzer metadata: %#v", dynamicInfo)
		}
		if !dynamicInfo.Optional || len(dynamicInfo.Resources) == 0 {
			t.Fatalf("dynamic capability metadata is not explicit: %#v", dynamicInfo)
		}
		if expectedFamily, ok := wanted[dynamicInfo.Name]; ok && dynamicInfo.Family != expectedFamily {
			t.Fatalf("%s family = %q, want %q", dynamicInfo.Name, dynamicInfo.Family, expectedFamily)
		}
		seen[dynamicInfo.Name] = true
	}
	for name := range wanted {
		if !seen[name] {
			t.Fatalf("expected dynamic analyzer %q was not registered", name)
		}
	}
}

func TestDynamicAnalyzersDetectGatewayOLMAndIntegrationFailures(t *testing.T) {
	gatewayFixture := dynamicObject(gatewayGVR, "apps", "public", map[string]interface{}{
		"spec": map[string]interface{}{
			"gatewayClassName": "edge",
			"listeners":        []interface{}{map[string]interface{}{"name": "http", "protocol": "HTTP", "port": int64(0)}},
		},
		"status": map[string]interface{}{"conditions": []interface{}{
			map[string]interface{}{"type": "Programmed", "status": "False", "reason": "Invalid", "message": "listener cannot be programmed"},
		}},
	})
	client := newDynamicTestClient(
		dynamicObject(gatewayClassGVR, "", "edge", map[string]interface{}{
			"spec": map[string]interface{}{"controllerName": "example.net/gateway-controller"},
			"status": map[string]interface{}{"conditions": []interface{}{
				map[string]interface{}{"type": "Accepted", "status": "False", "reason": "InvalidParameters", "message": "controller rejected class"},
			}},
		}),
		gatewayFixture,
		dynamicObject(httpRouteGVR, "apps", "frontend", map[string]interface{}{
			"spec": map[string]interface{}{
				"parentRefs": []interface{}{map[string]interface{}{"name": "public"}},
				"rules":      []interface{}{map[string]interface{}{"backendRefs": []interface{}{map[string]interface{}{"name": "missing", "port": int64(8080)}}}},
			},
			"status": map[string]interface{}{"parents": []interface{}{map[string]interface{}{
				"parentRef": map[string]interface{}{"name": "public"},
				"conditions": []interface{}{
					map[string]interface{}{"type": "Accepted", "status": "False", "reason": "NoMatchingListener", "message": "no listener matched"},
					map[string]interface{}{"type": "ResolvedRefs", "status": "False", "reason": "BackendNotFound", "message": "backend missing"},
				},
			}}},
		}),
		dynamicObject(clusterServiceVersionGVR, "operators", "sample.v1.0.0", map[string]interface{}{
			"spec":   map[string]interface{}{"displayName": "Sample"},
			"status": map[string]interface{}{"phase": "Failed", "message": "install failed"},
		}),
		dynamicObject(kedaScaledObjectGVR, "apps", "worker", map[string]interface{}{
			"spec": map[string]interface{}{"scaleTargetRef": map[string]interface{}{"name": "worker"}},
			"status": map[string]interface{}{"conditions": []interface{}{
				map[string]interface{}{"type": "Ready", "status": "False", "reason": "ScaledObjectCheckFailed", "message": "target is unavailable"},
			}},
		}),
	)
	set := NewDynamicAnalyzerSet(client)
	set.EnableFamily("integration")
	issues, err := set.Analyze(context.Background(), "")
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(issues) < 7 {
		t.Fatalf("Analyze() returned %d issues, want gateway, OLM, and integration findings: %#v", len(issues), issues)
	}

	wantCategories := []IssueCategory{
		CategoryGatewayClassNotAccepted,
		CategoryGatewayListenerInvalid,
		CategoryGatewayNotProgrammed,
		CategoryHTTPRouteParentNotAccepted,
		CategoryHTTPRouteRefsNotResolved,
		CategoryHTTPRouteBackendMissing,
		CategoryOLMResourceUnhealthy,
		CategoryIntegrationResourceUnhealthy,
	}
	for _, category := range wantCategories {
		if !hasIssueCategory(issues, category) {
			t.Errorf("Analyze() did not report category %q", category)
		}
	}
}

func TestHTTPRouteResolvesGatewayAndListenerSection(t *testing.T) {
	gateway := dynamicObject(gatewayGVR, "apps", "edge", map[string]interface{}{
		"spec": map[string]interface{}{
			"listeners": []interface{}{map[string]interface{}{
				"name":     "http",
				"protocol": "HTTP",
				"port":     int64(80),
				"allowedRoutes": map[string]interface{}{
					"namespaces": map[string]interface{}{"from": "All"},
				},
			}},
		},
	})
	client := newDynamicTestClient(gateway)
	spec := dynamicResourceSpec{GVR: httpRouteGVR, Kind: "HTTPRoute", Namespaced: true}
	validRoute := dynamicObject(httpRouteGVR, "apps", "valid", map[string]interface{}{
		"spec": map[string]interface{}{"parentRefs": []interface{}{map[string]interface{}{
			"name":        "edge",
			"namespace":   "apps",
			"sectionName": "http",
		}}},
	})
	if issues := analyzeHTTPRoute(dynamicClientContext(context.Background(), client), spec, validRoute); hasIssueCategory(issues, CategoryHTTPRouteParentNotAccepted) || hasIssueCategory(issues, CategoryHTTPRouteRefsNotResolved) {
		t.Fatalf("valid Gateway listener was rejected: %#v", issues)
	}

	wrongSection := validRoute.DeepCopy()
	wrongSection.Object["spec"].(map[string]interface{})["parentRefs"].([]interface{})[0].(map[string]interface{})["sectionName"] = "https"
	if issues := analyzeHTTPRoute(dynamicClientContext(context.Background(), client), spec, wrongSection); !hasIssueCategory(issues, CategoryHTTPRouteParentNotAccepted) {
		t.Fatalf("missing listener section was not reported: %#v", issues)
	}

	missingGateway := validRoute.DeepCopy()
	missingGateway.Object["spec"].(map[string]interface{})["parentRefs"].([]interface{})[0].(map[string]interface{})["name"] = "missing"
	if issues := analyzeHTTPRoute(dynamicClientContext(context.Background(), client), spec, missingGateway); !hasIssueCategory(issues, CategoryHTTPRouteRefsNotResolved) {
		t.Fatalf("missing Gateway was not reported: %#v", issues)
	}
}

func TestDynamicIntegrationFamiliesAreOptIn(t *testing.T) {
	client := newDynamicTestClient(dynamicObject(kedaScaledObjectGVR, "apps", "worker", map[string]interface{}{
		"status": map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": "Ready", "status": "False"}}},
	}))
	set := NewDynamicAnalyzerSet(client)
	issues, err := set.Analyze(context.Background(), "")
	if err != nil || len(issues) != 0 {
		t.Fatalf("inactive integration Analyze() = %#v, %v; want no execution", issues, err)
	}
	set.EnableFamily("integration")
	issues, err = set.Analyze(context.Background(), "")
	if err != nil || len(issues) == 0 {
		t.Fatalf("enabled integration Analyze() = %#v, %v; want finding", issues, err)
	}
}

func TestDynamicAnalyzerHonorsScanPlanScopeAndAnalyzerSelection(t *testing.T) {
	client := newDynamicTestClient(
		dynamicObject(gatewayGVR, "apps", "included", map[string]interface{}{
			"metadata": map[string]interface{}{"labels": map[string]interface{}{"team": "edge"}},
			"spec":     map[string]interface{}{"gatewayClassName": "edge"},
			"status":   map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": "Accepted", "status": "False", "message": "not accepted"}}},
		}),
		dynamicObject(gatewayGVR, "apps", "excluded-label", map[string]interface{}{
			"metadata": map[string]interface{}{"labels": map[string]interface{}{"team": "other"}},
			"spec":     map[string]interface{}{"gatewayClassName": "edge"},
		}),
		dynamicObject(gatewayGVR, "other", "excluded-namespace", map[string]interface{}{
			"metadata": map[string]interface{}{"labels": map[string]interface{}{"team": "edge"}},
			"spec":     map[string]interface{}{"gatewayClassName": "edge"},
		}),
	)
	plan := scanplan.Plan{
		IncludeNamespaces: []string{"apps"},
		LabelSelector:     "team=edge",
		Analyzers:         []string{"GatewayAnalyzer"},
	}
	ctx := scanplan.WithContext(context.Background(), plan)
	issues, err := NewDynamicAnalyzerSet(client).Analyze(ctx, "")
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if len(issues) != 1 || issues[0].Name != "included" {
		t.Fatalf("scoped issues = %#v, want only apps/included", issues)
	}
}

func TestDynamicAnalyzersTreatAbsentAndForbiddenCRDsAsUnavailable(t *testing.T) {
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gatewayClassGVR: "GatewayClassList"})
	client.PrependReactor("list", "gatewayclasses", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbiddenError(gatewayClassGVR)
	})

	set := NewDynamicAnalyzerSet(client)
	analyzer := dynamicAnalyzerByName(set, "GatewayClassAnalyzer")
	if analyzer == nil {
		t.Fatal("GatewayClassAnalyzer not found")
	}
	capability := analyzer.Capability(context.Background())
	if capability.State != DynamicCapabilityForbidden {
		t.Fatalf("forbidden capability state = %q, want %q: %#v", capability.State, DynamicCapabilityForbidden, capability)
	}
	if issues, err := analyzer.Analyze(context.Background(), ""); err != nil || len(issues) != 0 {
		t.Fatalf("forbidden Analyze() = issues %#v, err %v; want no findings or error", issues, err)
	}

	ab := dynamicAnalyzerByName(set, "ClusterServiceVersionAnalyzer")
	if ab == nil {
		t.Fatal("ClusterServiceVersionAnalyzer not found")
	}
	capability = ab.Capability(context.Background())
	if capability.State != DynamicCapabilityAbsent {
		t.Fatalf("absent capability state = %q, want %q: %#v", capability.State, DynamicCapabilityAbsent, capability)
	}
	if issues, err := ab.Analyze(context.Background(), ""); err != nil || len(issues) != 0 {
		t.Fatalf("absent Analyze() = issues %#v, err %v; want no findings or error", issues, err)
	}
}

func TestOptionalDynamicScannerPathLeavesDefaultTypedScannerUsable(t *testing.T) {
	typed := typedfake.NewSimpleClientset(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "apps"}})
	dynamicClient := fake.NewSimpleDynamicClient(runtime.NewScheme())
	optional := NewClusterScannerWithDynamicClient(typed, dynamicClient)
	if len(optional.DynamicAnalyzers()) == 0 {
		t.Fatal("optional scanner has no dynamic analyzers")
	}
	if len(optional.GetAnalyzers()) <= len(NewClusterScanner(typed).GetAnalyzers()) {
		t.Fatal("optional scanner did not expose dynamic analyzer metadata")
	}
	if _, err := optional.ScanDynamic(context.Background(), ""); err != nil {
		t.Fatalf("ScanDynamic() error = %v", err)
	}

	optional.SetDynamicClient(nil)
	if len(optional.DynamicAnalyzers()) != 0 {
		t.Fatal("SetDynamicClient(nil) left dynamic analyzers attached")
	}
	if _, err := optional.Scan(context.Background(), ""); err != nil {
		t.Fatalf("embedded typed Scan() error = %v", err)
	}
}

func dynamicObject(gvr schema.GroupVersionResource, namespace, name string, fields map[string]interface{}) *unstructured.Unstructured {
	kind := map[string]string{
		"gatewayclasses":                "GatewayClass",
		"gateways":                      "Gateway",
		"httproutes":                    "HTTPRoute",
		"referencegrants":               "ReferenceGrant",
		"clustercatalogs":               "ClusterCatalog",
		"clusterextensions":             "ClusterExtension",
		"clusterserviceversions":        "ClusterServiceVersion",
		"subscriptions":                 "Subscription",
		"installplans":                  "InstallPlan",
		"catalogsources":                "CatalogSource",
		"operatorgroups":                "OperatorGroup",
		"scaledobjects":                 "ScaledObject",
		"scaledjobs":                    "ScaledJob",
		"triggerauthentications":        "TriggerAuthentication",
		"clustertriggerauthentications": "ClusterTriggerAuthentication",
	}[gvr.Resource]
	if kind == "" {
		kind = gvr.Resource
	}
	object := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": gvr.Group + "/" + gvr.Version,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name": name,
		},
	}}
	if gvr.Group == "" {
		object.Object["apiVersion"] = gvr.Version
	}
	if namespace != "" {
		object.Object["metadata"].(map[string]interface{})["namespace"] = namespace
	}
	for key, value := range fields {
		if key == "metadata" {
			metadata, ok := value.(map[string]interface{})
			if ok {
				baseMetadata := object.Object["metadata"].(map[string]interface{})
				for metadataKey, metadataValue := range metadata {
					baseMetadata[metadataKey] = metadataValue
				}
				continue
			}
		}
		object.Object[key] = value
	}
	return object
}

func newDynamicTestClient(objects ...runtime.Object) *fake.FakeDynamicClient {
	listKinds := map[schema.GroupVersionResource]string{
		gatewayClassGVR:              "GatewayClassList",
		gatewayGVR:                   "GatewayList",
		httpRouteGVR:                 "HTTPRouteList",
		referenceGrantGVR:            "ReferenceGrantList",
		clusterCatalogGVR:            "ClusterCatalogList",
		clusterExtensionGVR:          "ClusterExtensionList",
		clusterServiceVersionGVR:     "ClusterServiceVersionList",
		subscriptionGVR:              "SubscriptionList",
		installPlanGVR:               "InstallPlanList",
		catalogSourceGVR:             "CatalogSourceList",
		operatorGroupGVR:             "OperatorGroupList",
		kedaScaledObjectGVR:          "ScaledObjectList",
		kedaScaledJobGVR:             "ScaledJobList",
		kedaTriggerAuthenticationGVR: "TriggerAuthenticationList",
		kedaClusterTriggerAuthGVR:    "ClusterTriggerAuthenticationList",
	}
	var nonGatewayObjects []runtime.Object
	var gatewayObjects []*unstructured.Unstructured
	for _, object := range objects {
		unstructuredObject, ok := object.(*unstructured.Unstructured)
		if ok && unstructuredObject.GetKind() == "Gateway" {
			gatewayObjects = append(gatewayObjects, unstructuredObject)
			continue
		}
		nonGatewayObjects = append(nonGatewayObjects, object)
	}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, nonGatewayObjects...)
	for _, object := range gatewayObjects {
		if err := client.Tracker().Create(gatewayGVR, object, object.GetNamespace()); err != nil {
			panic(err)
		}
	}
	return client
}

func hasIssueCategory(issues []*Issue, category IssueCategory) bool {
	for _, issue := range issues {
		if issue != nil && issue.Category == category {
			return true
		}
	}
	return false
}

func dynamicAnalyzerByName(set *DynamicAnalyzerSet, name string) DynamicAnalyzer {
	for _, analyzer := range set.DynamicAnalyzers() {
		if analyzer.Info().Name == name {
			return analyzer.(DynamicAnalyzer)
		}
	}
	return nil
}

func forbiddenError(gvr schema.GroupVersionResource) error {
	return apierrors.NewForbidden(gvr.GroupResource(), "", errors.New("access denied"))
}
