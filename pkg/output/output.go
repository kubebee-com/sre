// Package output contains the stable, secret-safe presentation contract for
// scan reports. The scanner remains responsible for collecting findings;
// this package owns serialization and human-readable rendering.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"gopkg.in/yaml.v3"
)

const OutputSchemaVersion = "output/v1"

type Format string

const (
	FormatJSON  Format = "json"
	FormatTable Format = "table"
	FormatYAML  Format = "yaml"
	FormatRaw   Format = "raw"
)

type Options struct {
	Format       Format
	SecretValues []string
	IncludeStats bool
}

type Stats struct {
	FindingCount        int `json:"finding_count" yaml:"finding_count"`
	AnalyzerCount       int `json:"analyzer_count" yaml:"analyzer_count"`
	FailedAnalyzerCount int `json:"failed_analyzer_count" yaml:"failed_analyzer_count"`
}

type document struct {
	SchemaVersion string                    `json:"schema_version" yaml:"schema_version"`
	Scope         scanplan.EffectiveScope   `json:"scope" yaml:"scope"`
	Stats         Stats                     `json:"stats" yaml:"stats"`
	Findings      []*scanner.SanitizedIssue `json:"findings" yaml:"findings"`
	Analyzers     []scanner.AnalyzerRun     `json:"analyzers" yaml:"analyzers"`
}

func ParseFormat(value string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(value))) {
	case "", FormatJSON:
		return FormatJSON, nil
	case FormatTable:
		return FormatTable, nil
	case FormatYAML:
		return FormatYAML, nil
	case FormatRaw:
		return FormatRaw, nil
	default:
		return "", fmt.Errorf("unsupported output format %q", value)
	}
}

func Render(writer io.Writer, report *scanner.ScanReport, options Options) error {
	if writer == nil {
		return errors.New("output writer is required")
	}
	if report == nil {
		return errors.New("scan report is required")
	}
	format, err := ParseFormat(string(options.Format))
	if err != nil {
		return err
	}
	redactor := sanitizer.RedactorForSecrets(options.SecretValues...)
	document := buildDocument(report, redactor)

	switch format {
	case FormatTable:
		return renderTable(writer, document)
	case FormatYAML:
		encoder := yaml.NewEncoder(writer)
		defer encoder.Close()
		return encoder.Encode(document)
	case FormatRaw:
		encoded, err := json.Marshal(document)
		if err != nil {
			return fmt.Errorf("encode raw report: %w", err)
		}
		_, err = writer.Write(encoded)
		return err
	default:
		encoded, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return fmt.Errorf("encode JSON report: %w", err)
		}
		encoded = append(encoded, '\n')
		_, err = writer.Write(encoded)
		return err
	}
}

func buildDocument(report *scanner.ScanReport, redactor *sanitizer.Redactor) document {
	if redactor == nil {
		redactor = sanitizer.DefaultRedactor()
	}
	scope := report.Scope
	scope.SchemaVersion = redactor.SanitizeText(scope.SchemaVersion)
	scope.IncludeNamespaces = sanitizeStrings(redactor, scope.IncludeNamespaces)
	scope.ExcludeNamespaces = sanitizeStrings(redactor, scope.ExcludeNamespaces)
	scope.LabelSelector = redactor.SanitizeText(scope.LabelSelector)
	scope.Kinds = sanitizeStrings(redactor, scope.Kinds)
	scope.Names = sanitizeStrings(redactor, scope.Names)
	scope.Analyzers = sanitizeStrings(redactor, scope.Analyzers)

	findings := make([]*scanner.SanitizedIssue, 0, len(report.Issues))
	for _, issue := range report.Issues {
		if issue != nil {
			findings = append(findings, scanner.SanitizeIssueWithRedactor(issue, redactor))
		}
	}
	analyzers := make([]scanner.AnalyzerRun, 0, len(report.Analyzers))
	failed := 0
	for _, run := range report.Analyzers {
		copy := run
		copy.Info.Name = redactor.SanitizeText(copy.Info.Name)
		copy.Info.Resource = redactor.SanitizeText(copy.Info.Resource)
		copy.Info.Description = redactor.SanitizeText(copy.Info.Description)
		copy.Info.DocsURL = redactor.SanitizeURL(copy.Info.DocsURL)
		copy.Info.ParentKind = redactor.SanitizeText(copy.Info.ParentKind)
		copy.Error = redactor.SanitizeText(copy.Error)
		if strings.TrimSpace(copy.Error) != "" {
			failed++
		}
		analyzers = append(analyzers, copy)
	}
	return document{
		SchemaVersion: OutputSchemaVersion,
		Scope:         scope,
		Stats: Stats{
			FindingCount:        len(findings),
			AnalyzerCount:       len(analyzers),
			FailedAnalyzerCount: failed,
		},
		Findings:  findings,
		Analyzers: analyzers,
	}
}

func sanitizeStrings(redactor *sanitizer.Redactor, values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = redactor.SanitizeText(value)
	}
	return result
}

func renderTable(writer io.Writer, report document) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "SEVERITY\tCATEGORY\tRESOURCE\tNAMESPACE\tNAME\tSUMMARY"); err != nil {
		return err
	}
	for _, issue := range report.Findings {
		if issue == nil {
			continue
		}
		if _, err := fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\n",
			issue.Severity, issue.Category, issue.Kind, issue.Namespace, issue.Name, issue.Summary); err != nil {
			return err
		}
	}
	return table.Flush()
}
