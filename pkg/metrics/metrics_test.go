package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/cache"
)

func TestRegistryRecordsBoundedOperationMetrics(t *testing.T) {
	registry := NewRegistry()
	registry.ObserveScan(nil, 25*time.Millisecond)
	registry.ObserveScan(context.DeadlineExceeded, 50*time.Millisecond)
	registry.ObserveAnalyzer("PodAnalyzer", nil, 10*time.Millisecond)
	registry.ObserveAnalyzer(strings.Repeat("x", 256), errors.New("failed"), time.Millisecond)
	registry.ObserveProviderRequest("OpenAI/Codex (model)", errors.New("failed"))
	registry.ObserveProviderUsage("OpenAI/Codex (model)", 10, 20, 30)
	registry.ObserveError("remediation")

	gathered, err := registry.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	if len(gathered) != 8 {
		t.Fatalf("metric family count = %d, want 8", len(gathered))
	}
	for _, family := range gathered {
		if !strings.HasPrefix(family.GetName(), "sre_") {
			t.Errorf("metric family %q is outside sre namespace", family.GetName())
		}
	}
}

func TestRegistryRecordsProviderUsageAndBoundedErrors(t *testing.T) {
	registry := NewRegistry()
	registry.ObserveProviderUsage(strings.Repeat("provider/", 32), 7, 11, 18)
	registry.ObserveProviderUsage("provider", -1, 2, 0)
	registry.ObserveError(strings.Repeat("source", 64))

	families, err := registry.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	var tokens, errorsMetric bool
	for _, family := range families {
		switch family.GetName() {
		case "sre_provider_tokens_total":
			tokens = true
			if len(family.GetMetric()) != 3 {
				t.Fatalf("provider token series = %d, want 3", len(family.GetMetric()))
			}
		case "sre_errors_total":
			errorsMetric = true
			for _, metric := range family.GetMetric() {
				for _, label := range metric.GetLabel() {
					if label.GetName() == "source" && len(label.GetValue()) > 32 {
						t.Fatalf("error source label was not bounded: %q", label.GetValue())
					}
				}
			}
		}
	}
	if !tokens || !errorsMetric {
		t.Fatalf("provider token/error metric families missing: tokens=%t errors=%t", tokens, errorsMetric)
	}
	snapshot := registry.Snapshot()
	if !snapshot.ProviderUsageSeen || snapshot.InputTokens != 7 || snapshot.OutputTokens != 13 || snapshot.TotalTokens != 18 {
		t.Fatalf("snapshot usage = %#v, want input=7 output=13 total=18", snapshot)
	}
	if snapshot.ErrorCounts["unknown"] != 1 {
		t.Fatalf("snapshot errors = %#v, want bounded unknown error", snapshot.ErrorCounts)
	}
}

func TestRegistryRecordsCacheHitAndMissWithBoundedLabels(t *testing.T) {
	registry := NewRegistry()
	registry.ObserveCacheOperation("lookup", "hit")
	registry.ObserveCacheOperation("lookup", "miss")
	registry.ObserveCacheOperation(strings.Repeat("x", 256), "unexpected")

	cacheMetrics, err := registry.Gatherer().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	var found bool
	for _, family := range cacheMetrics {
		if family.GetName() != "sre_cache_operations_total" {
			continue
		}
		found = true
		if len(family.GetMetric()) != 25 {
			t.Fatalf("cache metric series = %d, want 25 bounded series", len(family.GetMetric()))
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "operation" && len(label.GetValue()) > 16 {
					t.Fatalf("cache operation label was not bounded: %q", label.GetValue())
				}
			}
		}
	}
	if !found {
		t.Fatal("cache operation metric family was not registered")
	}
}

var _ cache.OperationObserver = (*Registry)(nil)

func TestOperationStatusClassifiesWrappedCancellation(t *testing.T) {
	if got := operationStatus(errors.Join(errors.New("wrapped"), context.Canceled)); got != statusCanceled {
		t.Fatalf("operationStatus() = %q, want %q", got, statusCanceled)
	}
}
