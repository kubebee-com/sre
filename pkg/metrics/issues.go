package metrics

import (
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// IssueSeriesObservation carries bounded per-category issue totals for Prometheus export.
type IssueSeriesObservation struct {
	Category    string
	Group       string
	Severity    string
	RawCount    int
	FoldedCount int
}

type issueMetricSet struct {
	mu     sync.Mutex
	active *prometheus.GaugeVec
	folded *prometheus.GaugeVec
}

var (
	issueMetricsRegistryMu sync.Mutex
	issueMetricsByGatherer = make(map[prometheus.Gatherer]*issueMetricSet)
)

// ObserveIssueSeries exports current active raw and folded issue counts under
// bounded category, finding_group, and severity labels.
func (m *Registry) ObserveIssueSeries(observations []IssueSeriesObservation) {
	if m == nil {
		return
	}
	set := ensureIssueMetricSet(m.Gatherer())
	if set == nil {
		return
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	set.active.Reset()
	set.folded.Reset()
	for _, obs := range observations {
		cat := boundMetricLabel(obs.Category, 64)
		grp := boundMetricLabel(obs.Group, 32)
		sev := boundMetricLabel(strings.ToUpper(obs.Severity), 16)
		set.active.WithLabelValues(cat, grp, sev).Set(float64(obs.RawCount))
		set.folded.WithLabelValues(cat, grp, sev).Set(float64(obs.FoldedCount))
	}
}

func ensureIssueMetricSet(gatherer prometheus.Gatherer) *issueMetricSet {
	if gatherer == nil {
		return nil
	}
	registerer, ok := gatherer.(prometheus.Registerer)
	if !ok {
		return nil
	}
	issueMetricsRegistryMu.Lock()
	defer issueMetricsRegistryMu.Unlock()
	if existing, exists := issueMetricsByGatherer[gatherer]; exists {
		return existing
	}
	active := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "sre",
		Name:      "active_issues",
		Help:      "Current raw active Kubernetes anomalies grouped by category, finding group, and severity.",
	}, []string{"category", "finding_group", "severity"})
	folded := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "sre",
		Name:      "folded_issues",
		Help:      "Current folded Kubernetes anomaly groups by category, finding group, and severity.",
	}, []string{"category", "finding_group", "severity"})
	if err := registerMetricCollector(registerer, &active); err != nil {
		return nil
	}
	if err := registerMetricCollector(registerer, &folded); err != nil {
		return nil
	}
	set := &issueMetricSet{active: active, folded: folded}
	issueMetricsByGatherer[gatherer] = set
	return set
}

func registerMetricCollector(registerer prometheus.Registerer, target **prometheus.GaugeVec) error {
	if err := registerer.Register(*target); err != nil {
		if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
			if existing, castOK := already.ExistingCollector.(*prometheus.GaugeVec); castOK {
				*target = existing
				return nil
			}
		}
		return err
	}
	return nil
}

func boundMetricLabel(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return unknownLabel
	}
	if len(value) > maxBytes {
		return value[:maxBytes]
	}
	return value
}
