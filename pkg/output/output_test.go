package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
)

func testReport() *scanner.ScanReport {
	when := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	return &scanner.ScanReport{
		SchemaVersion: scanplan.SchemaVersion,
		Scope: scanplan.Plan{
			IncludeNamespaces: []string{"payments"},
			Kinds:             []string{"Pod"},
			Analyzers:         []string{"PodAnalyzer"},
			MaxConcurrency:    2,
			Timeout:           time.Minute,
		}.EffectiveScope(),
		Issues: []*scanner.Issue{{
			ID:            "issue-1",
			Namespace:     "payments",
			Kind:          "Pod",
			Name:          "checkout-0",
			Severity:      scanner.SeverityHigh,
			Category:      scanner.CategoryCrashLoop,
			Summary:       "crash output-secret",
			Details:       "details output-secret",
			LogsSnippet:   "logs output-secret",
			Events:        []string{"event output-secret"},
			SpecSnippet:   "spec output-secret",
			Parent:        &scanner.ResourceRef{Kind: "Deployment", Name: "checkout", UID: "parent-output-secret"},
			DocsURL:       "https://docs.example.test/pods",
			FirstObserved: when,
			LastObserved:  when,
		}},
		Analyzers: []scanner.AnalyzerRun{{
			Info: scanner.AnalyzerInfo{
				Name:        "PodAnalyzer",
				Resource:    "Pod",
				Description: "pod checks",
				DocsURL:     "https://docs.example.test/pods",
				ParentKind:  "Deployment",
			},
			IssueCount: 1,
			Duration:   "5ms",
			Error:      "request failed output-secret",
			StartedAt:  when,
			FinishedAt: when.Add(5 * time.Millisecond),
		}},
		StartedAt:  when,
		FinishedAt: when.Add(5 * time.Millisecond),
		Duration:   "5ms",
	}
}

func TestRenderJSONIncludesContractAndSanitizesFindings(t *testing.T) {
	var got bytes.Buffer
	if err := Render(&got, testReport(), Options{Format: FormatJSON, SecretValues: []string{"output-secret"}}); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if strings.Contains(got.String(), "output-secret") {
		t.Fatalf("JSON output leaked secret: %s", got.String())
	}
	var document struct {
		SchemaVersion string           `json:"schema_version"`
		Scope         map[string]any   `json:"scope"`
		Stats         map[string]any   `json:"stats"`
		Findings      []map[string]any `json:"findings"`
		Analyzers     []map[string]any `json:"analyzers"`
	}
	if err := json.Unmarshal(got.Bytes(), &document); err != nil {
		t.Fatalf("decode JSON output: %v\n%s", err, got.String())
	}
	if document.SchemaVersion != OutputSchemaVersion || document.Scope["label_selector"] != nil || len(document.Findings) != 1 || len(document.Analyzers) != 1 {
		t.Fatalf("unexpected output envelope: %#v", document)
	}
	if document.Findings[0]["docs_url"] != "https://docs.example.test/pods" || document.Findings[0]["parent"] == nil {
		t.Fatalf("finding omitted docs or parent: %#v", document.Findings[0])
	}
	if document.Stats["finding_count"] != float64(1) || document.Stats["failed_analyzer_count"] != float64(1) {
		t.Fatalf("unexpected stats: %#v", document.Stats)
	}
}

func TestRenderSupportsTableYAMLAndRaw(t *testing.T) {
	for _, format := range []Format{FormatTable, FormatYAML, FormatRaw} {
		t.Run(string(format), func(t *testing.T) {
			var got bytes.Buffer
			if err := Render(&got, testReport(), Options{Format: format, SecretValues: []string{"output-secret"}}); err != nil {
				t.Fatalf("Render(%s) error = %v", format, err)
			}
			if got.Len() == 0 || strings.Contains(got.String(), "output-secret") {
				t.Fatalf("Render(%s) output = %q", format, got.String())
			}
			if format == FormatTable && !strings.Contains(got.String(), "SEVERITY") {
				t.Fatalf("table output missing header: %s", got.String())
			}
			if format == FormatRaw {
				var raw map[string]any
				if err := json.Unmarshal(got.Bytes(), &raw); err != nil {
					t.Fatalf("raw output is not compact JSON: %v", err)
				}
			}
		})
	}
}

func TestParseFormatRejectsUnknownValues(t *testing.T) {
	if _, err := ParseFormat("toml"); err == nil {
		t.Fatal("ParseFormat(toml) unexpectedly succeeded")
	}
}
