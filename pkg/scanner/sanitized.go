package scanner

import (
	"encoding/json"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
)

// RedactionReport is the scanner-visible form of sanitizer.RedactionReport.
type RedactionReport = sanitizer.RedactionReport

// SanitizedIssue is the only issue projection intended for providers and external sinks.
type SanitizedIssue struct {
	AnalyzerNames         []string                  `json:"analyzer_names,omitempty"`
	ID                    string                    `json:"id"`
	Namespace             string                    `json:"namespace"`
	Kind                  string                    `json:"kind"`
	Name                  string                    `json:"name"`
	TargetUID             string                    `json:"target_uid,omitempty"`
	TargetResourceVersion string                    `json:"target_resource_version,omitempty"`
	Severity              Severity                  `json:"severity"`
	Category              IssueCategory             `json:"category"`
	Summary               string                    `json:"summary"`
	Details               string                    `json:"details"`
	LogsSnippet           string                    `json:"logs_snippet,omitempty"`
	Events                []string                  `json:"events,omitempty"`
	SpecSnippet           string                    `json:"spec_snippet,omitempty"`
	FirstObserved         time.Time                 `json:"first_observed"`
	LastObserved          time.Time                 `json:"last_observed"`
	Parent                *ResourceRef              `json:"parent,omitempty"`
	DocsURL               string                    `json:"docs_url,omitempty"`
	Report                sanitizer.RedactionReport `json:"-"`
}

// Sanitized returns a redacted copy of the issue and never mutates the source.
func (i *Issue) Sanitized(secretValues ...string) *SanitizedIssue {
	return SanitizeIssue(i, secretValues...)
}

// SanitizeIssue returns a typed, redacted projection of an issue.
func SanitizeIssue(issue *Issue, secretValues ...string) *SanitizedIssue {
	return SanitizeIssueWithRedactor(issue, sanitizer.RedactorForSecrets(secretValues...))
}

// SanitizeIssueWithRedactor returns a projection using an existing redaction policy.
func SanitizeIssueWithRedactor(issue *Issue, redactor *sanitizer.Redactor) *SanitizedIssue {
	if redactor == nil {
		redactor = sanitizer.DefaultRedactor()
	}
	return sanitizeIssueWithRedactor(issue, redactor)
}

// SanitizeIssues returns redacted projections for all non-nil issues.
func SanitizeIssues(issues []*Issue, secretValues ...string) []*SanitizedIssue {
	redactor := sanitizer.NewRedactor(secretValues...)
	result := make([]*SanitizedIssue, 0, len(issues))
	for _, issue := range issues {
		if issue != nil {
			result = append(result, SanitizeIssueWithRedactor(issue, redactor))
		}
	}
	return result
}

func sanitizeIssueWithRedactor(issue *Issue, redactor *sanitizer.Redactor) *SanitizedIssue {
	if issue == nil {
		return nil
	}
	result := &SanitizedIssue{
		Severity:      issue.Severity,
		Category:      issue.Category,
		FirstObserved: issue.FirstObserved,
		LastObserved:  issue.LastObserved,
		Report:        sanitizer.RedactionReport{},
	}
	for _, name := range issue.AnalyzerNames {
		result.AnalyzerNames = appendUniqueField(result.AnalyzerNames, sanitizeAndRecord(redactor, name, "analyzer_names", &result.Report))
	}
	result.ID = sanitizeAndRecord(redactor, issue.ID, "id", &result.Report)
	result.Namespace = sanitizeAndRecord(redactor, issue.Namespace, "namespace", &result.Report)
	result.Kind = sanitizeAndRecord(redactor, issue.Kind, "kind", &result.Report)
	result.Name = sanitizeAndRecord(redactor, issue.Name, "name", &result.Report)
	result.TargetUID = sanitizeAndRecord(redactor, issue.TargetUID, "target_uid", &result.Report)
	result.TargetResourceVersion = sanitizeAndRecord(redactor, issue.TargetResourceVersion, "target_resource_version", &result.Report)
	result.Summary = sanitizeAndRecord(redactor, issue.Summary, "summary", &result.Report)
	result.Details = sanitizeAndRecord(redactor, issue.Details, "details", &result.Report)
	result.LogsSnippet = sanitizeAndRecord(redactor, issue.LogsSnippet, "logs_snippet", &result.Report)
	result.SpecSnippet = sanitizeAndRecord(redactor, issue.SpecSnippet, "spec_snippet", &result.Report)
	result.DocsURL = redactor.SanitizeURL(issue.DocsURL)
	if issue.Parent != nil {
		result.Parent = &ResourceRef{
			Namespace: sanitizeAndRecord(redactor, issue.Parent.Namespace, "parent.namespace", &result.Report),
			Kind:      sanitizeAndRecord(redactor, issue.Parent.Kind, "parent.kind", &result.Report),
			Name:      sanitizeAndRecord(redactor, issue.Parent.Name, "parent.name", &result.Report),
			UID:       sanitizeAndRecord(redactor, issue.Parent.UID, "parent.uid", &result.Report),
		}
	}

	if len(issue.Events) > 0 {
		result.Events = make([]string, len(issue.Events))
		for index, event := range issue.Events {
			result.Events[index] = sanitizeAndRecord(redactor, event, "events", &result.Report)
		}
	}
	return result
}

func sanitizeAndRecord(redactor *sanitizer.Redactor, value, field string, report *sanitizer.RedactionReport) string {
	sanitized, fieldReport := redactor.SanitizeStructuredTextWithReport(value)
	if fieldReport.RedactedCount > 0 {
		report.RedactedCount += fieldReport.RedactedCount
		report.Fields = appendUniqueField(report.Fields, field)
	}
	return sanitized
}

func appendUniqueField(fields []string, additions ...string) []string {
	for _, addition := range additions {
		found := false
		for _, field := range fields {
			if field == addition {
				found = true
				break
			}
		}
		if !found {
			fields = append(fields, addition)
		}
	}
	return fields
}

// AsIssue creates a sanitized Issue value for compatibility with the provider interface.
func (i *SanitizedIssue) AsIssue() *Issue {
	if i == nil {
		return nil
	}
	events := append([]string(nil), i.Events...)
	result := &Issue{
		AnalyzerNames:         append([]string(nil), i.AnalyzerNames...),
		ID:                    i.ID,
		Namespace:             i.Namespace,
		Kind:                  i.Kind,
		Name:                  i.Name,
		TargetUID:             i.TargetUID,
		TargetResourceVersion: i.TargetResourceVersion,
		Severity:              i.Severity,
		Category:              i.Category,
		Summary:               i.Summary,
		Details:               i.Details,
		LogsSnippet:           i.LogsSnippet,
		Events:                events,
		SpecSnippet:           i.SpecSnippet,
		FirstObserved:         i.FirstObserved,
		LastObserved:          i.LastObserved,
		DocsURL:               i.DocsURL,
	}
	if i.Parent != nil {
		result.Parent = &ResourceRef{
			Namespace: i.Parent.Namespace,
			Kind:      i.Parent.Kind,
			Name:      i.Parent.Name,
			UID:       i.Parent.UID,
		}
	}
	return result
}

// ToIssue is an alias for callers that prefer conversion terminology.
func (i *SanitizedIssue) ToIssue() *Issue {
	return i.AsIssue()
}

// MarshalJSON prevents accidental serialization of the raw issue by another sink.
func (i Issue) MarshalJSON() ([]byte, error) {
	return marshalSanitizedIssue(SanitizeIssue(&i))
}

// MarshalJSON keeps even a manually assembled sanitized projection under the
// configured process-wide policy.
func (i SanitizedIssue) MarshalJSON() ([]byte, error) {
	return marshalSanitizedIssue(sanitizeIssueWithRedactor(i.AsIssue(), sanitizer.DefaultRedactor()))
}

func marshalSanitizedIssue(issue *SanitizedIssue) ([]byte, error) {
	type issueJSON SanitizedIssue
	if issue == nil {
		return []byte("null"), nil
	}
	wire := issueJSON(*issue)
	return json.Marshal(wire)
}
