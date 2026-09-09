package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

func (m *Registry) initPlaybookMetrics() {
	m.playbookTasksTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sre", Name: "playbook_tasks_total",
		Help: "Total structured playbook tasks by operation, provider, and status.",
	}, []string{"operation", "provider", "status"})
	m.playbookTokensTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sre", Name: "playbook_tokens_total",
		Help: "Reported tokens for structured playbook tasks.",
	}, []string{"operation", "provider", "kind"})
	m.playbookOutcomesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "sre", Name: "playbook_outcomes_total",
		Help: "Total playbook pipeline outcomes.",
	}, []string{"operation", "outcome"})
	m.registry.MustRegister(m.playbookTasksTotal, m.playbookTokensTotal, m.playbookOutcomesTotal)
}

// ObservePlaybookTask deliberately uses fixed labels: neither model output nor
// a configured endpoint can create a new series or expose credentials.
func (m *Registry) ObservePlaybookTask(operation, provider string, input, output, total int64, err error) {
	if m == nil || m.playbookTasksTotal == nil {
		return
	}
	op, name := playbookOperationLabel(operation), playbookProviderLabel(provider)
	m.playbookTasksTotal.WithLabelValues(op, name, operationStatus(err)).Inc()
	if total <= 0 && input >= 0 && output >= 0 && input <= 1_000_000_000 && output <= 1_000_000_000 {
		total = input + output
	}
	for kind, value := range map[string]int64{"input": input, "output": output, "total": total} {
		if value <= 0 {
			continue
		}
		if value > 1_000_000_000 {
			value = 1_000_000_000
		}
		m.playbookTokensTotal.WithLabelValues(op, name, kind).Add(float64(value))
	}
}

func (m *Registry) ObservePlaybookOutcome(operation, outcome string) {
	if m == nil || m.playbookOutcomesTotal == nil {
		return
	}
	op := unknownLabel
	switch operation {
	case "import", "ingestion", "digest", "guardrail", "resolve", "resolution", "learn", "learning", "transition":
		op = operation
	}
	result := unknownLabel
	switch outcome {
	case "approved", "retired", "accepted", "imported", "resolved", "rejected", "guardrail_rejected", "no_match", "proposal", "draft", "verified", "failed", "unverified", "disabled", "error", "duplicate", "skipped", "success":
		result = outcome
	}
	m.playbookOutcomesTotal.WithLabelValues(op, result).Inc()
}

func playbookOperationLabel(operation string) string {
	switch operation {
	case "digest", "normalize", "resolve", "learn":
		operation = "playbook." + operation
	}
	switch operation {
	case "playbook.digest", "playbook.normalize", "playbook.resolve", "playbook.learn":
		return operation
	default:
		return unknownLabel
	}
}

func playbookProviderLabel(provider string) string {
	switch name := strings.ToLower(strings.TrimSpace(provider)); name {
	case "codex", "openai", "harness", "claude", "anthropic", "deepseek", "azure", "bedrock", "sagemaker", "groq", "gemini", "ollama", "custom", "rule-based", "noop":
		return name
	default:
		return unknownLabel
	}
}
