package triage

import (
	"encoding/json"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

// SanitizedDiagnosis is the projection safe for proposals, APIs, and notifications.
type SanitizedDiagnosis struct {
	IssueID         string                    `json:"issue_id"`
	Summary         string                    `json:"summary"`
	RootCause       string                    `json:"root_cause"`
	Severity        scanner.Severity          `json:"severity"`
	RemediationPlan string                    `json:"remediation_plan"`
	ActionType      ActionType                `json:"action_type"`
	ProposedCommand string                    `json:"proposed_command"`
	TargetReplicas  *int32                    `json:"target_replicas,omitempty"`
	ConfidenceScore float64                   `json:"confidence_score"`
	ProviderName    string                    `json:"provider_name"`
	Report          sanitizer.RedactionReport `json:"-"`
}

// Sanitized returns a redacted copy of a diagnosis without changing the source.
func (d *Diagnosis) Sanitized(secretValues ...string) *SanitizedDiagnosis {
	return d.SanitizedWithRedactor(sanitizer.RedactorForSecrets(secretValues...))
}

// SanitizedWithRedactor returns a projection using an existing redaction policy.
func (d *Diagnosis) SanitizedWithRedactor(redactor *sanitizer.Redactor) *SanitizedDiagnosis {
	if d == nil {
		return nil
	}
	if redactor == nil {
		redactor = sanitizer.DefaultRedactor()
	}
	result := &SanitizedDiagnosis{
		Severity:        d.Severity,
		ActionType:      d.ActionType,
		TargetReplicas:  cloneInt32Pointer(d.TargetReplicas),
		ConfidenceScore: d.ConfidenceScore,
	}
	result.IssueID = sanitizeDiagnosisField(redactor, d.IssueID, "issue_id", &result.Report)
	result.Summary = sanitizeDiagnosisField(redactor, d.Summary, "summary", &result.Report)
	result.RootCause = sanitizeDiagnosisField(redactor, d.RootCause, "root_cause", &result.Report)
	result.RemediationPlan = sanitizeDiagnosisField(redactor, d.RemediationPlan, "remediation_plan", &result.Report)
	result.ProposedCommand = sanitizeDiagnosisField(redactor, d.ProposedCommand, "proposed_command", &result.Report)
	result.ProviderName = sanitizeDiagnosisField(redactor, d.ProviderName, "provider_name", &result.Report)
	return result
}

func sanitizeDiagnosisField(redactor *sanitizer.Redactor, value, field string, report *sanitizer.RedactionReport) string {
	sanitized, fieldReport := redactor.SanitizeStructuredTextWithReport(value)
	if fieldReport.RedactedCount > 0 {
		report.RedactedCount += fieldReport.RedactedCount
		report.Fields = appendUniqueDiagnosisField(report.Fields, field)
	}
	return sanitized
}

func appendUniqueDiagnosisField(fields []string, additions ...string) []string {
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

// MarshalJSON prevents an accidental raw diagnosis serialization from becoming a sink.
func (d Diagnosis) MarshalJSON() ([]byte, error) {
	return marshalSanitizedDiagnosis(d.SanitizedWithRedactor(sanitizer.DefaultRedactor()))
}

// MarshalJSON keeps a manually assembled sanitized projection under the
// configured process-wide policy as well.
func (d SanitizedDiagnosis) MarshalJSON() ([]byte, error) {
	return marshalSanitizedDiagnosis(d.AsDiagnosis().SanitizedWithRedactor(sanitizer.DefaultRedactor()))
}

// AsDiagnosis returns a typed copy of a sanitized diagnosis.
func (d *SanitizedDiagnosis) AsDiagnosis() *Diagnosis {
	if d == nil {
		return nil
	}
	return &Diagnosis{
		IssueID:         d.IssueID,
		Summary:         d.Summary,
		RootCause:       d.RootCause,
		Severity:        d.Severity,
		RemediationPlan: d.RemediationPlan,
		ActionType:      d.ActionType,
		ProposedCommand: d.ProposedCommand,
		TargetReplicas:  cloneInt32Pointer(d.TargetReplicas),
		ConfidenceScore: d.ConfidenceScore,
		ProviderName:    d.ProviderName,
	}
}

func cloneInt32Pointer(value *int32) *int32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func marshalSanitizedDiagnosis(diagnosis *SanitizedDiagnosis) ([]byte, error) {
	type diagnosisJSON SanitizedDiagnosis
	if diagnosis == nil {
		return []byte("null"), nil
	}
	wire := diagnosisJSON(*diagnosis)
	return json.Marshal(wire)
}
