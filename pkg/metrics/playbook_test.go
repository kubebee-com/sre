package metrics

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPlaybookTaskMetricsKeepUsageAndErrorsByTask(t *testing.T) {
	r := NewRegistry()
	r.ObservePlaybookTask("playbook.digest", "codex", 5, 3, 8, nil)
	r.ObservePlaybookTask("playbook.resolve", "codex", 0, 0, 0, context.DeadlineExceeded)
	r.ObservePlaybookOutcome("learning", "draft")
	expected := `
# HELP sre_playbook_tasks_total Total structured playbook tasks by operation, provider, and status.
# TYPE sre_playbook_tasks_total counter
sre_playbook_tasks_total{operation="playbook.digest",provider="codex",status="success"} 1
sre_playbook_tasks_total{operation="playbook.resolve",provider="codex",status="timeout"} 1
# HELP sre_playbook_tokens_total Reported tokens for structured playbook tasks.
# TYPE sre_playbook_tokens_total counter
sre_playbook_tokens_total{kind="input",operation="playbook.digest",provider="codex"} 5
sre_playbook_tokens_total{kind="output",operation="playbook.digest",provider="codex"} 3
sre_playbook_tokens_total{kind="total",operation="playbook.digest",provider="codex"} 8
# HELP sre_playbook_outcomes_total Total playbook pipeline outcomes.
# TYPE sre_playbook_outcomes_total counter
sre_playbook_outcomes_total{operation="learning",outcome="draft"} 1
`
	if err := testutil.GatherAndCompare(r.Gatherer(), strings.NewReader(expected), "sre_playbook_tasks_total", "sre_playbook_tokens_total", "sre_playbook_outcomes_total"); err != nil {
		t.Fatal(err)
	}
}

func TestPlaybookMetricLabelsDoNotExposeUntrustedValues(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 100; i++ {
		untrusted := fmt.Sprintf("https://user:secret-%d@private.test/prompt", i)
		r.ObservePlaybookTask(untrusted, untrusted, -1, -1, -1, fmt.Errorf("%s", untrusted))
		r.ObservePlaybookOutcome(untrusted, untrusted)
	}
	families, err := r.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "sre_playbook_") {
			continue
		}
		if len(family.Metric) != 1 {
			t.Fatalf("unbounded series in %s: %d", family.GetName(), len(family.Metric))
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if strings.Contains(label.GetValue(), "secret") || strings.Contains(label.GetValue(), "private") {
					t.Fatalf("unsafe label: %s", label.GetName())
				}
			}
		}
	}
}

func TestPlaybookTaskShortOperationUsesCanonicalLabel(t *testing.T) {
	r := NewRegistry()
	r.ObservePlaybookTask("digest", "codex", 1, 1, 2, nil)
	r.ObservePlaybookOutcome("transition", "guardrail_rejected")
	r.ObservePlaybookOutcome("transition", "approved")
	r.ObservePlaybookOutcome("transition", "retired")
	r.ObservePlaybookOutcome("digest", "imported")
	r.ObservePlaybookOutcome("resolve", "resolved")
	families, _ := r.Gatherer().Gather()
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "sre_playbook_") {
			continue
		}
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetValue() == "unknown" {
					t.Fatalf("known service event became unknown in %s", family.GetName())
				}
			}
		}
	}
}
