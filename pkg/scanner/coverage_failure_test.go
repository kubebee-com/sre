package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanplan"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestCoverageUnknownSchemaPreservesKnownFindings(t *testing.T) {
	for _, schema := range []string{"", "unknown/v9"} {
		t.Run(schema, func(t *testing.T) {
			s := NewMemoryHistoryStore()
			recordCoverage(t, s, coverageReport(10, scanplan.Default(), coverageIssue("a", "one")))
			r := coverageReport(20, scanplan.Default())
			r.Scope.SchemaVersion = schema
			recordCoverage(t, s, r)
			if len(activeHistory(t, s)) != 1 {
				t.Fatal("unknown scope schema resolved known finding")
			}
		})
	}
}
func TestServiceIncompleteCoveragePreservesPriorFindings(t *testing.T) {
	for _, mode := range []string{"slice-forbidden", "endpoint-forbidden", "pagination", "pagination-ready"} {
		t.Run(mode, func(t *testing.T) {
			client := fake.NewSimpleClientset(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"}})
			s := NewClusterScannerWithHistory(client, NewMemoryHistoryStore())
			p := scanPlanForAnalyzer("ServiceAnalyzer")
			if _, err := s.ScanWithPlan(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			if mode == "endpoint-forbidden" {
				client.PrependReactor("get", "endpoints", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("forbidden") })
			} else {
				client.PrependReactor("list", "endpointslices", func(k8stesting.Action) (bool, runtime.Object, error) {
					if mode == "slice-forbidden" {
						return true, nil, errors.New("forbidden")
					}
					list := &discoveryv1.EndpointSliceList{ListMeta: metav1.ListMeta{Continue: "more"}}
					if mode == "pagination-ready" {
						ready := true
						list.Items = []discoveryv1.EndpointSlice{{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{discoveryv1.LabelServiceName: "web"}}, Endpoints: []discoveryv1.Endpoint{{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}}}}
					}
					return true, list, nil
				})
			}
			r, err := s.ScanWithPlan(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Analyzers) != 1 || r.Analyzers[0].Error == "" {
				t.Fatal("incomplete Service observation reported successful coverage")
			}
			rows, _ := s.History().List()
			found := false
			for _, row := range rows {
				if row.Issue.Category == CategoryServiceNoEndpoint && !row.Resolved {
					found = true
				}
			}
			if !found {
				t.Fatal("incomplete observation resolved prior NoEndpoints finding")
			}
			if mode != "pagination-ready" && !hasIssue(r.Issues, "web", CategoryServiceEndpointError) {
				t.Fatal("lost useful endpoint error finding")
			}
		})
	}
}

type coverageRoundTripper func(*http.Request) (*http.Response, error)

func (f coverageRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type coverageBrokenBody struct{ io.Reader }

func (b coverageBrokenBody) Read(p []byte) (int, error) {
	n, _ := b.Reader.Read(p)
	return n, errors.New("stream interrupted")
}
func (b coverageBrokenBody) Close() error { return nil }
func TestLogReadFailureMarksCoverageIncomplete(t *testing.T) {
	base, _ := url.Parse("http://logs.invalid")
	client := logErrorClient{Interface: fake.NewSimpleClientset(restartedPod("worker")), base: base, httpClient: &http.Client{Transport: coverageRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: coverageBrokenBody{Reader: strings.NewReader("ERROR useful partial evidence\n")}}, nil
	})}}
	s := NewClusterScanner(client)
	r, err := s.ScanWithPlan(context.Background(), scanPlanForAnalyzer("LogAnalyzer"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Analyzers) != 1 || r.Analyzers[0].Error == "" {
		t.Fatal("failed log stream reported successful coverage")
	}
	if len(r.Issues) == 0 {
		t.Fatal("lost useful partial log finding")
	}
}
func TestCoverageUIDOrderingAcrossAnalyzersAndCategories(t *testing.T) {
	s := NewMemoryHistoryStore()
	newer := coverageIssue("a", "one")
	newer.ID = "log"
	newer.TargetUID = "new"
	newer.Category = CategoryPodLogError
	newer.AnalyzerNames = []string{"LogAnalyzer"}
	r := coverageReport(20, scanplan.Default(), newer)
	r.Analyzers[0].Info.Name = "LogAnalyzer"
	recordCoverage(t, s, r)
	older := coverageIssue("a", "one")
	older.TargetUID = "old"
	recordCoverage(t, s, coverageReport(10, scanplan.Default(), older))
	rows, _ := s.List()
	if len(rows) != 1 {
		t.Fatal("old UID resurrected across category/analyzer boundary")
	}
}
func TestCoverageOlderIndependentFindingOnSameUIDRetained(t *testing.T) {
	s := NewMemoryHistoryStore()
	newer := coverageIssue("a", "one")
	newer.ID = "event"
	newer.TargetUID = "same"
	newer.AnalyzerNames = []string{"EventAnalyzer"}
	r := coverageReport(20, scanplan.Default(), newer)
	r.Analyzers[0].Info.Name = "EventAnalyzer"
	recordCoverage(t, s, r)
	older := coverageIssue("a", "one")
	older.TargetUID = "same"
	recordCoverage(t, s, coverageReport(10, scanplan.Default(), older))
	rows, _ := s.List()
	if len(rows) != 2 {
		t.Fatal("independent observation on same UID was discarded")
	}
}
func TestDynamicDependencyForbiddenPreservesPriorFinding(t *testing.T) {
	client := coverageDynamicClient(httpRouteGVR, "HTTPRouteList", dynamicObject(httpRouteGVR, "apps", "route", map[string]interface{}{"spec": map[string]interface{}{"rules": []interface{}{map[string]interface{}{"backendRefs": []interface{}{map[string]interface{}{"name": "backend", "port": int64(80)}}}}}}))
	client.PrependReactor("list", "httproutes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetResource().Version == "v1beta1" {
			return true, &unstructured.UnstructuredList{}, nil
		}
		return false, nil, nil
	})
	s := NewClusterScannerWithDynamicClient(nil, client)
	s.SetHistoryStore(NewMemoryHistoryStore())
	p := scanPlanForAnalyzer("HTTPRouteAnalyzer")
	first, err := s.ScanWithPlan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if first.Analyzers[0].Error != "" {
		t.Fatalf("fixture coverage incomplete: %s", first.Analyzers[0].Error)
	}
	if !hasIssue(first.Issues, "route", CategoryHTTPRouteBackendMissing) {
		t.Fatal("missing fixture BackendMissing finding")
	}
	client.PrependReactor("get", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(serviceGVR.GroupResource(), "backend", errors.New("denied"))
	})
	r, err := s.ScanWithPlan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Analyzers[0].Error == "" {
		t.Fatal("dependency forbidden reported successful dynamic coverage")
	}
	rows, _ := s.History().List()
	found := false
	for _, row := range rows {
		if row.Issue.Category == CategoryHTTPRouteBackendMissing && !row.Resolved {
			found = true
		}
	}
	if !found {
		t.Fatal("forbidden dependency resolved prior backend finding")
	}
}
func TestDynamicPaginatedCoveragePreservesPriorFinding(t *testing.T) {
	client := coverageDynamicClient(gatewayClassGVR, "GatewayClassList", dynamicObject(gatewayClassGVR, "", "edge", map[string]interface{}{"spec": map[string]interface{}{"controllerName": "example.net/controller"}, "status": map[string]interface{}{"conditions": []interface{}{map[string]interface{}{"type": "Accepted", "status": "False"}}}}))
	s := NewClusterScannerWithDynamicClient(nil, client)
	s.SetHistoryStore(NewMemoryHistoryStore())
	p := scanPlanForAnalyzer("GatewayClassAnalyzer")
	first, err := s.ScanWithPlan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if first.Analyzers[0].Error != "" {
		t.Fatalf("fixture coverage incomplete: %s", first.Analyzers[0].Error)
	}
	if len(first.Issues) == 0 {
		t.Fatal("missing fixture issue")
	}
	client.PrependReactor("list", "gatewayclasses", func(k8stesting.Action) (bool, runtime.Object, error) {
		list := &unstructured.UnstructuredList{}
		list.SetContinue("more")
		return true, list, nil
	})
	r, err := s.ScanWithPlan(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Analyzers[0].Error == "" {
		t.Fatal("partial list reported complete dynamic coverage")
	}
	if len(activeHistory(t, s.History())) == 0 {
		t.Fatal("partial list resolved prior issue")
	}
}

func coverageDynamicClient(gvr schema.GroupVersionResource, listKind string, object runtime.Object) *dynamicfake.FakeDynamicClient {
	beta := gvr
	beta.Version = "v1beta1"
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{gvr: listKind, beta: listKind}, object)
}

func TestCoverageLateMergedProvenanceMatchesChronologicalOrder(t *testing.T) {
	for _, order := range []string{"chronological", "late"} {
		t.Run(order, func(t *testing.T) {
			store := NewMemoryHistoryStore()
			issue := coverageIssue("a", "one")
			issue.AnalyzerNames = []string{"PodAnalyzer", "EventAnalyzer"}
			older := coverageReport(10, scanplan.Default(), issue)
			older.Analyzers = append(older.Analyzers, AnalyzerRun{Info: AnalyzerInfo{Name: "EventAnalyzer", Resource: "Event"}})
			newer := coverageReport(20, scanPlanForAnalyzer("PodAnalyzer"))
			if order == "chronological" {
				recordCoverage(t, store, older)
				recordCoverage(t, store, newer)
			} else {
				recordCoverage(t, store, newer)
				recordCoverage(t, store, older)
			}
			active := activeHistory(t, store)
			if len(active) != 1 || active["a/one"] == nil || len(active["a/one"].AnalyzerNames) != 2 {
				t.Fatalf("partial newer coverage discarded merged provenance: %#v", active)
			}
			// Full newer coverage can resolve all contributing observations in either order.
			complete := coverageReport(30, scanplan.Default())
			complete.Analyzers = append(complete.Analyzers, AnalyzerRun{Info: AnalyzerInfo{Name: "EventAnalyzer", Resource: "Event"}})
			recordCoverage(t, store, complete)
			if len(activeHistory(t, store)) != 0 {
				t.Fatal("complete newer coverage did not resolve finding")
			}
		})
	}
}
