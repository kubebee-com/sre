package scanner

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

func TestScanServicesScopesAndBoundsEndpointSliceLookup(t *testing.T) {
	ready := true
	client := fake.NewSimpleClientset(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: "default",
			Labels:    map[string]string{"team": "sre"},
		},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
	})

	var got k8stesting.ListRestrictions
	client.PrependReactor("list", "endpointslices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		listAction, ok := action.(k8stesting.ListAction)
		if !ok {
			t.Fatalf("EndpointSlice action type = %T, want ListAction", action)
		}
		got = listAction.GetListRestrictions()
		return true, &discoveryv1.EndpointSliceList{Items: []discoveryv1.EndpointSlice{{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-1",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "web"},
			},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			}},
		}}}, nil
	})

	plan := scanplan.Default()
	plan.Names = []string{"web"}
	plan.LabelSelector = "team=sre"
	ctx := scanplan.WithContext(context.Background(), plan)
	issues, err := NewClusterScanner(client).scanServices(ctx, "default")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}
	if hasIssue(issues, "web", CategoryServiceNoEndpoint) {
		t.Fatalf("scanServices() reported no endpoints despite the owned ready EndpointSlice: %#v", issues)
	}

	wantSelector := labels.Set{discoveryv1.LabelServiceName: "web"}.AsSelector().String()
	if got.Labels.String() != wantSelector {
		t.Fatalf("EndpointSlice label selector = %q, want %q", got.Labels.String(), wantSelector)
	}
	if got.Fields.String() != "" {
		t.Fatalf("EndpointSlice field selector = %q, want empty dependency selector", got.Fields.String())
	}
}

func TestScanServicesIgnoresUnownedEndpointSlices(t *testing.T) {
	ready := true
	client := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{Name: "unowned", Namespace: "default"},
			Endpoints: []discoveryv1.Endpoint{{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			}},
		},
	)

	issues, err := NewClusterScanner(client).scanServices(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}
	if !hasIssue(issues, "web", CategoryServiceNoEndpoint) {
		t.Fatalf("scanServices() counted an EndpointSlice without a Service owner label: %#v", issues)
	}
}

func TestScanServicesIgnoresEndpointSliceEntriesWithoutAddresses(t *testing.T) {
	ready := true
	client := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
		},
		&discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-1",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "web"},
			},
			Endpoints: []discoveryv1.Endpoint{{Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
		},
	)

	issues, err := NewClusterScanner(client).scanServices(context.Background(), "default")
	if err != nil {
		t.Fatalf("scanServices() error = %v", err)
	}
	if !hasIssue(issues, "web", CategoryServiceNoEndpoint) {
		t.Fatalf("scanServices() counted an EndpointSlice entry without an address: %#v", issues)
	}
}

func TestScanServicesBoundsEndpointSliceItems(t *testing.T) {
	ready := true
	items := make([]discoveryv1.EndpointSlice, 101)
	for index := range items {
		items[index].ObjectMeta = metav1.ObjectMeta{
			Name:      "web-" + string(rune('a'+index%26)),
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "web"},
		}
	}
	items[100].Endpoints = []discoveryv1.Endpoint{{
		Addresses:  []string{"10.0.0.101"},
		Conditions: discoveryv1.EndpointConditions{Ready: &ready},
	}}

	client := fake.NewSimpleClientset(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default"},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "web"}},
	})
	client.PrependReactor("list", "endpointslices", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, &discoveryv1.EndpointSliceList{ListMeta: metav1.ListMeta{Continue: "more"}, Items: items}, nil
	})

	issues, err := NewClusterScanner(client).scanServices(context.Background(), "default")
	if err == nil {
		t.Fatal("incomplete bounded observation must return an analyzer error")
	}
	if hasIssue(issues, "web", CategoryServiceNoEndpoint) {
		t.Fatalf("scanServices() reported no endpoints from an incomplete bounded result: %#v", issues)
	}
	if !hasIssue(issues, "web", CategoryServiceEndpointError) {
		t.Fatalf("scanServices() did not report an incomplete bounded result: %#v", issues)
	}
}

func TestEndpointSliceListOptionsUseFixedLimit(t *testing.T) {
	options := endpointSliceListOptions(&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web"}})
	if options.Limit != maxEndpointSlicesPerService {
		t.Fatalf("EndpointSlice list limit = %d, want %d", options.Limit, maxEndpointSlicesPerService)
	}
	if options.Limit <= 0 {
		t.Fatalf("EndpointSlice list limit = %d, want positive bound", options.Limit)
	}
}
