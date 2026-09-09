package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanplan"
)

type registryTestAnalyzer struct{ name string }

func (a registryTestAnalyzer) Info() AnalyzerInfo {
	return AnalyzerInfo{Name: a.name, Resource: "Pod", Description: "test analyzer", DocsURL: "https://example.invalid/analyzer"}
}

func (a registryTestAnalyzer) Analyze(context.Context, string) ([]*Issue, error) {
	return []*Issue{{Kind: "Pod", Name: "registered", Summary: "custom finding"}}, nil
}

func TestAnalyzerRegistryValidatesAndSnapshotsCustomAnalyzers(t *testing.T) {
	registry := NewAnalyzerRegistry()
	analyzer := registryTestAnalyzer{name: "CustomAnalyzer"}
	if err := registry.Register(analyzer); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if err := registry.Register(analyzer); !errors.Is(err, ErrAnalyzerDuplicate) {
		t.Fatalf("duplicate Register() error = %v, want ErrAnalyzerDuplicate", err)
	}
	if got := registry.List(); len(got) != 1 || got[0].Info().Name != analyzer.name {
		t.Fatalf("List() = %#v, want registered analyzer", got)
	}
	if err := registry.Unregister("customanalyzer"); err != nil {
		t.Fatalf("Unregister() error = %v", err)
	}
	if _, ok := registry.Get(analyzer.name); ok {
		t.Fatal("Get() returned an analyzer after unregister")
	}
}

func TestClusterScannerCustomAnalyzerUsesScanContract(t *testing.T) {
	scanner := NewClusterScanner(nil)
	if err := scanner.RegisterAnalyzer(registryTestAnalyzer{name: "CustomAnalyzer"}); err != nil {
		t.Fatalf("RegisterAnalyzer() error = %v", err)
	}
	plan := scanPlanForAnalyzer("CustomAnalyzer")
	report, err := scanner.ScanWithPlan(context.Background(), plan)
	if err != nil {
		t.Fatalf("ScanWithPlan() error = %v", err)
	}
	if len(report.Issues) != 1 || report.Issues[0].DocsURL == "" {
		t.Fatalf("custom report = %#v, want one documented issue", report)
	}
}

func scanPlanForAnalyzer(name string) scanplan.Plan {
	return scanplan.Plan{SchemaVersion: scanplan.SchemaVersion, Analyzers: []string{name}, MaxConcurrency: 1, Timeout: scanplan.DefaultScanTimeout}
}
