package metrics

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	statusSuccess  = "success"
	statusCanceled = "canceled"
	statusTimeout  = "timeout"
	statusError    = "error"
	unknownLabel   = "unknown"
)

// Registry contains the process metrics owned by one SRE server instance.
// Keeping a private registry prevents duplicate-registration panics in tests
// and lets embedders decide where these metrics are exposed.
type Registry struct {
	registry              *prometheus.Registry
	scansTotal            *prometheus.CounterVec
	scanDuration          prometheus.Histogram
	analyzerRunsTotal     *prometheus.CounterVec
	analyzerDuration      *prometheus.HistogramVec
	cacheOperationsTotal  *prometheus.CounterVec
	providerRequestsTotal *prometheus.CounterVec
	providerTokensTotal   *prometheus.CounterVec
	playbookTasksTotal    *prometheus.CounterVec
	playbookTokensTotal   *prometheus.CounterVec
	playbookOutcomesTotal *prometheus.CounterVec
	errorsTotal           *prometheus.CounterVec
	snapshotMu            sync.RWMutex
	errorCounts           map[string]uint64
	providerInputTokens   uint64
	providerOutputTokens  uint64
	providerTotalTokens   uint64
	providerUsageSeen     bool
}

// Snapshot is the bounded in-process projection used by authenticated status
// consumers. It contains counters only and never includes provider payloads.
type Snapshot struct {
	ErrorCounts       map[string]uint64
	InputTokens       uint64
	OutputTokens      uint64
	TotalTokens       uint64
	ProviderUsageSeen bool
}

// NewRegistry creates a registry with bounded label dimensions. Analyzer names
// are the explicitly registered analyzer names, while status values are
// limited to the four values returned by operationStatus.
func NewRegistry() *Registry {
	registry := prometheus.NewRegistry()
	metrics := &Registry{
		registry: registry,
		scansTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sre",
			Name:      "scans_total",
			Help:      "Total number of cluster scans by terminal status.",
		}, []string{"status"}),
		scanDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "sre",
			Name:      "scan_duration_seconds",
			Help:      "Duration of cluster scans in seconds.",
			Buckets:   prometheus.DefBuckets,
		}),
		analyzerRunsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sre",
			Name:      "analyzer_runs_total",
			Help:      "Total number of analyzer runs by analyzer and terminal status.",
		}, []string{"analyzer", "status"}),
		analyzerDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "sre",
			Name:      "analyzer_duration_seconds",
			Help:      "Duration of analyzer runs in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"analyzer"}),
		cacheOperationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sre",
			Name:      "cache_operations_total",
			Help:      "Total cache operations by operation and bounded outcome.",
		}, []string{"operation", "status"}),
		providerRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sre",
			Name:      "provider_requests_total",
			Help:      "Total provider requests by bounded provider and terminal status.",
		}, []string{"provider", "status"}),
		providerTokensTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sre",
			Name:      "provider_tokens_total",
			Help:      "Total provider tokens reported by bounded provider and token kind.",
		}, []string{"provider", "kind"}),
		errorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "sre",
			Name:      "errors_total",
			Help:      "Total runtime errors by bounded subsystem source.",
		}, []string{"source"}),
		errorCounts: map[string]uint64{},
	}
	registry.MustRegister(metrics.scansTotal)
	registry.MustRegister(metrics.scanDuration)
	registry.MustRegister(metrics.analyzerRunsTotal)
	registry.MustRegister(metrics.analyzerDuration)
	registry.MustRegister(metrics.cacheOperationsTotal)
	registry.MustRegister(metrics.providerRequestsTotal)
	registry.MustRegister(metrics.providerTokensTotal)
	registry.MustRegister(metrics.errorsTotal)
	metrics.initPlaybookMetrics()
	for _, status := range []string{statusSuccess, statusCanceled, statusTimeout, statusError} {
		metrics.scansTotal.WithLabelValues(status)
	}
	for _, operation := range []string{"get", "lookup", "set", "remove", "list", "purge"} {
		for _, status := range []string{"hit", "miss", "success", "error"} {
			metrics.cacheOperationsTotal.WithLabelValues(operation, status)
		}
	}
	for _, source := range []string{"scan", "analyzer", "provider", "cache", "remediation", unknownLabel} {
		metrics.errorsTotal.WithLabelValues(source)
	}
	return metrics
}

// Gatherer returns the registry for promhttp.HandlerFor or another exporter.
func (m *Registry) Gatherer() prometheus.Gatherer {
	if m == nil || m.registry == nil {
		return prometheus.NewRegistry()
	}
	return m.registry
}

// ObserveScan records a completed scan. A nil error is success; cancellation
// and deadline are kept distinct because they indicate different operators'
// actions, while all other failures share one low-cardinality status.
func (m *Registry) ObserveScan(err error, duration time.Duration) {
	if m == nil {
		return
	}
	m.scansTotal.WithLabelValues(operationStatus(err)).Inc()
	if err != nil {
		m.ObserveError("scan")
	}
	m.scanDuration.Observe(duration.Seconds())
}

// ObserveAnalyzer records one analyzer invocation.
func (m *Registry) ObserveAnalyzer(name string, err error, duration time.Duration) {
	if m == nil {
		return
	}
	m.analyzerRunsTotal.WithLabelValues(analyzerLabel(name), operationStatus(err)).Inc()
	if err != nil {
		m.ObserveError("analyzer")
	}
	m.analyzerDuration.WithLabelValues(analyzerLabel(name)).Observe(duration.Seconds())
}

// ObserveCacheOperation records a cache operation using fixed operation and
// outcome vocabularies. Unknown values collapse to an error label so callers
// cannot create unbounded metric cardinality.
func (m *Registry) ObserveCacheOperation(operation, status string) {
	if m == nil {
		return
	}
	m.cacheOperationsTotal.WithLabelValues(cacheOperationLabel(operation), cacheStatusLabel(status)).Inc()
	if strings.TrimSpace(status) == "error" {
		m.ObserveError("cache")
	}
}

// ObserveProviderRequest records one provider operation. Provider names are
// reduced to a stable label so model/endpoint details cannot create an
// unbounded Prometheus series. A failed request also increments the aggregate
// provider error counter used by the dashboard.
func (m *Registry) ObserveProviderRequest(provider string, err error) {
	if m == nil {
		return
	}
	status := statusSuccess
	if err != nil {
		status = statusError
		m.ObserveError("provider")
	}
	m.providerRequestsTotal.WithLabelValues(providerLabel(provider), status).Inc()
}

// ObserveProviderUsage records usage reported by a provider response. Missing
// or negative values are ignored; a missing metric remains an explicit
// unavailable state in the dashboard instead of being reported as zero.
func (m *Registry) ObserveProviderUsage(provider string, prompt, completion, total int64) {
	if m == nil {
		return
	}
	values := map[string]int64{
		"prompt":     prompt,
		"completion": completion,
		"total":      total,
	}
	if values["total"] <= 0 && values["prompt"] >= 0 && values["completion"] >= 0 {
		values["total"] = values["prompt"] + values["completion"]
	}
	m.snapshotMu.Lock()
	if prompt > 0 {
		m.providerInputTokens += uint64(prompt)
	}
	if completion > 0 {
		m.providerOutputTokens += uint64(completion)
	}
	if values["total"] > 0 {
		m.providerTotalTokens += uint64(values["total"])
	}
	if prompt > 0 || completion > 0 || values["total"] > 0 {
		m.providerUsageSeen = true
	}
	m.snapshotMu.Unlock()
	for kind, value := range values {
		if value > 0 {
			m.providerTokensTotal.WithLabelValues(providerLabel(provider), kind).Add(float64(value))
		}
	}
}

// ObserveError records a low-cardinality subsystem error for dashboard and
// Prometheus consumers.
func (m *Registry) ObserveError(source string) {
	if m == nil {
		return
	}
	label := errorSourceLabel(source)
	m.errorsTotal.WithLabelValues(label).Inc()
	m.snapshotMu.Lock()
	m.errorCounts[label]++
	m.snapshotMu.Unlock()
}

// Snapshot returns a copy of the bounded status counters. The copy keeps
// callers from sharing mutable state with concurrent metric observations.
func (m *Registry) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{ErrorCounts: map[string]uint64{}}
	}
	m.snapshotMu.RLock()
	defer m.snapshotMu.RUnlock()
	counts := make(map[string]uint64, len(m.errorCounts))
	for source, count := range m.errorCounts {
		counts[source] = count
	}
	return Snapshot{
		ErrorCounts:       counts,
		InputTokens:       m.providerInputTokens,
		OutputTokens:      m.providerOutputTokens,
		TotalTokens:       m.providerTotalTokens,
		ProviderUsageSeen: m.providerUsageSeen,
	}
}

func operationStatus(err error) string {
	switch {
	case err == nil:
		return statusSuccess
	case errors.Is(err, context.Canceled):
		return statusCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return statusTimeout
	default:
		return statusError
	}
}

func analyzerLabel(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return unknownLabel
	}
	if len(name) > 128 {
		return name[:128]
	}
	return name
}

func cacheOperationLabel(operation string) string {
	switch strings.TrimSpace(operation) {
	case "get", "lookup", "set", "remove", "list", "purge":
		return strings.TrimSpace(operation)
	default:
		return unknownLabel
	}
}

func cacheStatusLabel(status string) string {
	switch strings.TrimSpace(status) {
	case "hit", "miss", "success", "error":
		return strings.TrimSpace(status)
	default:
		return "error"
	}
}

func providerLabel(provider string) string {
	provider = strings.TrimSpace(strings.ToLower(provider))
	if provider == "" {
		return unknownLabel
	}
	for index, char := range provider {
		if char == '/' || char == '(' || char == ' ' {
			provider = provider[:index]
			break
		}
	}
	provider = strings.Trim(provider, "-_.")
	if provider == "" {
		return unknownLabel
	}
	if len(provider) > 32 {
		return provider[:32]
	}
	return provider
}

func errorSourceLabel(source string) string {
	switch strings.TrimSpace(strings.ToLower(source)) {
	case "scan", "analyzer", "provider", "cache", "remediation":
		return strings.TrimSpace(strings.ToLower(source))
	default:
		return unknownLabel
	}
}
