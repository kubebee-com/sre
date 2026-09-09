package scanner

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

// DynamicClusterScanner is an opt-in facade that composes the existing typed
// scanner with the optional dynamic CRD analyzers. The original
// ClusterScanner type and its default fake-client behavior remain unchanged.
type DynamicClusterScanner struct {
	*ClusterScanner
	dynamicSet *DynamicAnalyzerSet
}

// NewClusterScannerWithDynamicClient creates a scanner with optional Gateway,
// OLM, and integration analyzers attached. The dynamic client is used only by
// the optional methods and may be nil.
func NewClusterScannerWithDynamicClient(client kubernetes.Interface, dynamicClient dynamic.Interface) *DynamicClusterScanner {
	return &DynamicClusterScanner{
		ClusterScanner: NewClusterScanner(client),
		dynamicSet:     NewDynamicAnalyzerSet(dynamicClient),
	}
}

// SetDynamicClient replaces or disables the optional dynamic analyzer client.
func (s *DynamicClusterScanner) SetDynamicClient(client dynamic.Interface) {
	if s == nil {
		return
	}
	if client == nil {
		s.dynamicSet = nil
		return
	}
	if s.dynamicSet == nil {
		s.dynamicSet = NewDynamicAnalyzerSet(client)
		return
	}
	s.dynamicSet.SetDynamicClient(client)
}

// SetMetricsObserver overrides the promoted typed-scanner method so optional
// dynamic analyzers use the same Prometheus registry as built-in analyzers.
func (s *DynamicClusterScanner) SetMetricsObserver(observer MetricsObserver) {
	if s == nil {
		return
	}
	if s.ClusterScanner != nil {
		s.ClusterScanner.SetMetricsObserver(observer)
	}
	if s.dynamicSet != nil {
		s.dynamicSet.SetMetricsObserver(observer)
	}
}

// DynamicAnalyzerSet returns the optional analyzer set, or nil when disabled.
func (s *DynamicClusterScanner) DynamicAnalyzerSet() *DynamicAnalyzerSet {
	if s == nil {
		return nil
	}
	return s.dynamicSet
}

// DynamicAnalyzers returns the optional analyzers in stable catalog order.
func (s *DynamicClusterScanner) DynamicAnalyzers() []Analyzer {
	if s == nil || s.dynamicSet == nil {
		return nil
	}
	return s.dynamicSet.DynamicAnalyzers()
}

// DynamicAnalyzerInfos returns metadata for optional analyzers without
// querying or serializing any CRD objects.
func (s *DynamicClusterScanner) DynamicAnalyzerInfos() []DynamicAnalyzerInfo {
	if s == nil || s.dynamicSet == nil {
		return nil
	}
	result := make([]DynamicAnalyzerInfo, 0, len(s.dynamicSet.DynamicAnalyzers()))
	for _, analyzer := range s.dynamicSet.DynamicAnalyzers() {
		if dynamicAnalyzer, ok := analyzer.(DynamicAnalyzer); ok {
			result = append(result, dynamicAnalyzer.DynamicInfo())
		}
	}
	return result
}

// DynamicCapabilities probes optional CRD access and reports absent/forbidden
// resources without returning those conditions as scan failures.
func (s *DynamicClusterScanner) DynamicCapabilities(ctx context.Context) []DynamicCapability {
	if s == nil || s.dynamicSet == nil {
		return nil
	}
	return s.dynamicSet.Capabilities(ctx)
}

// EnableIntegration activates one optional CRD family after the caller has
// completed its own allowlist, ownership, and permission checks.
func (s *DynamicClusterScanner) EnableIntegration(family string) {
	if s != nil && s.dynamicSet != nil {
		s.dynamicSet.EnableFamily(family)
	}
}

func (s *DynamicClusterScanner) DisableIntegration(family string) {
	if s != nil && s.dynamicSet != nil {
		s.dynamicSet.DisableFamily(family)
	}
}

// RegisteredAnalyzers exposes both catalogs for clients that explicitly opt
// into this facade. ClusterScanner.RegisteredAnalyzers remains typed-only.
func (s *DynamicClusterScanner) RegisteredAnalyzers() []Analyzer {
	if s == nil || s.ClusterScanner == nil {
		return nil
	}
	result := append([]Analyzer(nil), s.ClusterScanner.RegisteredAnalyzers()...)
	return append(result, s.DynamicAnalyzers()...)
}

// GetAnalyzers exposes both typed and optional analyzer metadata.
func (s *DynamicClusterScanner) GetAnalyzers() []AnalyzerInfo {
	if s == nil || s.ClusterScanner == nil {
		return nil
	}
	result := append([]AnalyzerInfo(nil), s.ClusterScanner.GetAnalyzers()...)
	for _, analyzer := range s.DynamicAnalyzers() {
		info := analyzer.Info()
		info.Enabled = true
		result = append(result, info)
	}
	return result
}

// ScanDynamic runs only the optional analyzers. It is useful to add CRD
// findings to an existing scan workflow without changing the default catalog.
func (s *DynamicClusterScanner) ScanDynamic(ctx context.Context, namespace string) ([]*Issue, error) {
	if s == nil || s.dynamicSet == nil {
		return nil, nil
	}
	return s.dynamicSet.Analyze(ctx, namespace)
}

// Scan composes the legacy typed scan and optional findings. Optional absent
// and forbidden resources do not produce errors; unexpected API errors are
// returned after any findings that were collected.
func (s *DynamicClusterScanner) Scan(ctx context.Context, namespace string) ([]*Issue, error) {
	if s == nil || s.ClusterScanner == nil {
		return nil, errors.New("scanner is unavailable")
	}
	plan := scanplan.Default()
	if strings.TrimSpace(namespace) != "" {
		plan.IncludeNamespaces = []string{strings.TrimSpace(namespace)}
	}
	report, err := s.scanWithPlan(ctx, plan, true)
	if report == nil {
		return nil, err
	}
	return report.Issues, err
}

// ScanWithPlan composes the versioned typed scan contract with optional
// analyzers. The typed scanner receives a filtered copy of the plan so it does
// not reject optional analyzer names as unknown.
func (s *DynamicClusterScanner) ScanWithPlan(ctx context.Context, plan scanplan.Plan) (*ScanReport, error) {
	return s.scanWithPlan(ctx, plan, false)
}

func (s *DynamicClusterScanner) scanWithPlan(ctx context.Context, plan scanplan.Plan, legacyErrors bool) (*ScanReport, error) {
	if s == nil || s.ClusterScanner == nil {
		return nil, errors.New("scanner is unavailable")
	}
	known := make([]string, 0, len(s.GetAnalyzers()))
	for _, info := range s.GetAnalyzers() {
		known = append(known, info.Name)
	}
	if err := plan.Validate(known); err != nil {
		return nil, err
	}

	dynamicNames := make(map[string]struct{})
	for _, analyzer := range s.DynamicAnalyzers() {
		dynamicNames[strings.ToLower(analyzer.Info().Name)] = struct{}{}
	}
	typedPlan := plan
	if len(plan.Analyzers) > 0 {
		typedPlan.Analyzers = make([]string, 0, len(plan.Analyzers))
		for _, name := range plan.Analyzers {
			if _, optional := dynamicNames[strings.ToLower(strings.TrimSpace(name))]; !optional {
				typedPlan.Analyzers = append(typedPlan.Analyzers, name)
			}
		}
		if len(typedPlan.Analyzers) == 0 {
			// A sentinel kind is accepted by the plan validator and matches no
			// typed analyzer, leaving the optional scan as the only execution.
			typedPlan.Kinds = []string{"__dynamic_optional_only__"}
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, planTimeout(plan.EffectiveScope().Timeout))
	defer cancel()
	report, typedErr := s.ClusterScanner.ScanWithPlan(context.WithValue(ctx, skipHistoryRecordingKey{}, true), typedPlan)
	if report == nil {
		return nil, typedErr
	}
	if s.dynamicSet == nil {
		report.Scope = plan.EffectiveScope()
		return report, errors.Join(typedErr, s.recordReport(report))
	}
	dynamicIssues, dynamicRuns, dynamicErr := s.dynamicSet.analyzeWithPlan(ctx, plan.NamespaceArgument(), &plan)
	report.Issues = append(report.Issues, dynamicIssues...)
	report.Issues = deduplicateIssues(report.Issues)
	report.Analyzers = append(report.Analyzers, dynamicRuns...)
	report.Scope = plan.EffectiveScope()
	report.FinishedAt = time.Now().UTC()
	report.Duration = report.FinishedAt.Sub(report.StartedAt).String()
	sort.Slice(report.Analyzers, func(i, j int) bool { return report.Analyzers[i].Info.Name < report.Analyzers[j].Info.Name })
	sortDynamicIssues(report.Issues)
	if ctx.Err() != nil {
		report.Error = classifyAnalyzerError(ctx.Err())
	}
	persistErr := s.recordReport(report)
	if !legacyErrors {
		dynamicErr = dynamicErrForScan(dynamicErr)
	}
	return report, errors.Join(typedErr, dynamicErr, ctx.Err(), persistErr)
}

func dynamicErrForScan(err error) error {
	// Analyzer API errors are represented in AnalyzerRun.Error just like the
	// typed scanner contract. Only cancellation/deadline should fail the scan.
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func sortDynamicIssues(issues []*Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		return issueLess(issues[i], issues[j])
	})
}
