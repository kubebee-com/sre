package scanplan

import (
	"context"
	"testing"
	"time"
)

func TestPlanValidationAndScope(t *testing.T) {
	plan := Plan{
		IncludeNamespaces: []string{"payments"},
		LabelSelector:     "app=checkout",
		Kinds:             []string{"Pod"},
		Names:             []string{"checkout-0"},
		Analyzers:         []string{"PodAnalyzer"},
	}
	if err := plan.Validate([]string{"PodAnalyzer", "ServiceAnalyzer"}); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !plan.Includes("pod", "checkout-0", "payments") {
		t.Fatal("expected matching object in plan scope")
	}
	if plan.Includes("Deployment", "checkout-0", "payments") {
		t.Fatal("unexpected kind in plan scope")
	}
	if plan.Includes("Pod", "other", "payments") {
		t.Fatal("unexpected name in plan scope")
	}
	if plan.Includes("Pod", "checkout-0", "default") {
		t.Fatal("unexpected namespace in plan scope")
	}
	if got := plan.NamespaceArgument(); got != "payments" {
		t.Fatalf("NamespaceArgument() = %q", got)
	}
	if got := plan.ListOptions().FieldSelector; got == "" {
		t.Fatal("expected metadata.name field selector")
	}
}

func TestPlanRejectsUnsafeOrUnknownValues(t *testing.T) {
	tests := []Plan{
		{LabelSelector: "app in ("},
		{Analyzers: []string{"Unknown"}},
		{MaxConcurrency: MaxConcurrency + 1},
		{Timeout: MaxScanTimeout + time.Second},
		{IncludeNamespaces: []string{"sre"}, ExcludeNamespaces: []string{"sre"}},
	}
	for _, plan := range tests {
		if err := plan.Validate([]string{"PodAnalyzer"}); err == nil {
			t.Fatalf("Validate(%+v) unexpectedly succeeded", plan)
		}
	}
}

func TestPlanContextRoundTrip(t *testing.T) {
	plan := Default()
	ctx := WithContext(context.Background(), plan)
	got, ok := FromContext(ctx)
	if !ok || got.MaxConcurrency != DefaultConcurrency {
		t.Fatalf("FromContext() = %+v, %t", got, ok)
	}
}
