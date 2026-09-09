package remediation

import (
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/triage"
)

// SanitizedProposal is the projection safe for APIs and external notifications.
type SanitizedProposal struct {
	ID                    string                     `json:"id"`
	IssueID               string                     `json:"issue_id"`
	CreatedBy             string                     `json:"created_by"`
	CreatedAt             time.Time                  `json:"created_at"`
	UpdatedAt             time.Time                  `json:"updated_at"`
	Namespace             string                     `json:"namespace"`
	Kind                  string                     `json:"kind"`
	Name                  string                     `json:"name"`
	TargetUID             string                     `json:"target_uid,omitempty"`
	TargetResourceVersion string                     `json:"target_resource_version,omitempty"`
	Revision              uint64                     `json:"revision"`
	ExpiresAt             *time.Time                 `json:"expires_at,omitempty"`
	Diagnosis             *triage.SanitizedDiagnosis `json:"diagnosis"`
	Status                ProposalStatus             `json:"status"`
	ApprovedBy            string                     `json:"approved_by,omitempty"`
	ApprovedAt            *time.Time                 `json:"approved_at,omitempty"`
	RejectedBy            string                     `json:"rejected_by,omitempty"`
	RejectedAt            *time.Time                 `json:"rejected_at,omitempty"`
	RejectionReason       string                     `json:"rejection_reason,omitempty"`
	ExecutionResult       string                     `json:"execution_result,omitempty"`
	ExecutionError        string                     `json:"execution_error,omitempty"`
	VerificationStatus    VerificationStatus         `json:"verification_status,omitempty"`
	VerificationError     string                     `json:"verification_error,omitempty"`
}

// Sanitized returns a redacted proposal copy without changing the source.
func (p *Proposal) Sanitized(secretValues ...string) *SanitizedProposal {
	return p.SanitizedWithRedactor(sanitizer.RedactorForSecrets(secretValues...))
}

// SanitizedWithRedactor returns a projection using an existing redaction policy.
func (p *Proposal) SanitizedWithRedactor(redactor *sanitizer.Redactor) *SanitizedProposal {
	if p == nil {
		return nil
	}
	if redactor == nil {
		redactor = sanitizer.DefaultRedactor()
	}
	result := &SanitizedProposal{
		ID:                    redactor.SanitizeText(p.ID),
		IssueID:               redactor.SanitizeText(p.IssueID),
		CreatedBy:             redactor.SanitizeText(p.CreatedBy),
		CreatedAt:             p.CreatedAt,
		UpdatedAt:             p.UpdatedAt,
		Namespace:             redactor.SanitizeText(p.Namespace),
		Kind:                  redactor.SanitizeText(p.Kind),
		Name:                  redactor.SanitizeText(p.Name),
		TargetUID:             redactor.SanitizeText(p.TargetUID),
		TargetResourceVersion: redactor.SanitizeText(p.TargetResourceVersion),
		Revision:              p.Revision,
		ExpiresAt:             p.ExpiresAt,
		Status:                p.Status,
		ApprovedBy:            redactor.SanitizeText(p.ApprovedBy),
		ApprovedAt:            p.ApprovedAt,
		RejectedBy:            redactor.SanitizeText(p.RejectedBy),
		RejectedAt:            p.RejectedAt,
		RejectionReason:       redactor.SanitizeText(p.RejectionReason),
		ExecutionResult:       redactor.SanitizeText(p.ExecutionResult),
		ExecutionError:        redactor.SanitizeText(p.ExecutionError),
		VerificationStatus:    p.VerificationStatus,
		VerificationError:     sanitizeAndBoundVerificationError(redactor, p.VerificationError),
	}
	if p.Diagnosis != nil {
		result.Diagnosis = p.Diagnosis.SanitizedWithRedactor(redactor)
	}
	return result
}

// MarshalJSON prevents an accidental raw proposal serialization from becoming a sink.
func (p Proposal) MarshalJSON() ([]byte, error) {
	return marshalSanitizedProposal((&p).SanitizedWithRedactor(sanitizer.DefaultRedactor()))
}

// MarshalJSON keeps a manually assembled sanitized projection under the
// configured process-wide policy as well.
func (p SanitizedProposal) MarshalJSON() ([]byte, error) {
	redactor := sanitizer.DefaultRedactor()
	copy := p
	copy.ID = redactor.SanitizeText(copy.ID)
	copy.IssueID = redactor.SanitizeText(copy.IssueID)
	copy.CreatedBy = redactor.SanitizeText(copy.CreatedBy)
	copy.Namespace = redactor.SanitizeText(copy.Namespace)
	copy.Kind = redactor.SanitizeText(copy.Kind)
	copy.Name = redactor.SanitizeText(copy.Name)
	copy.TargetUID = redactor.SanitizeText(copy.TargetUID)
	copy.TargetResourceVersion = redactor.SanitizeText(copy.TargetResourceVersion)
	copy.ApprovedBy = redactor.SanitizeText(copy.ApprovedBy)
	copy.RejectedBy = redactor.SanitizeText(copy.RejectedBy)
	copy.RejectionReason = redactor.SanitizeText(copy.RejectionReason)
	copy.ExecutionResult = redactor.SanitizeText(copy.ExecutionResult)
	copy.ExecutionError = redactor.SanitizeText(copy.ExecutionError)
	copy.VerificationError = sanitizeAndBoundVerificationError(redactor, copy.VerificationError)
	if copy.Diagnosis != nil {
		copy.Diagnosis = copy.Diagnosis.AsDiagnosis().SanitizedWithRedactor(redactor)
	}
	return marshalSanitizedProposal(&copy)
}

func sanitizeAndBoundVerificationError(redactor *sanitizer.Redactor, message string) string {
	if redactor == nil {
		redactor = sanitizer.DefaultRedactor()
	}
	message = redactor.SanitizeText(message)
	if len(message) <= maxExecutionErrorBytes {
		return message
	}
	message = message[:maxExecutionErrorBytes]
	for !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return message
}

func marshalSanitizedProposal(proposal *SanitizedProposal) ([]byte, error) {
	type proposalJSON SanitizedProposal
	if proposal == nil {
		return []byte("null"), nil
	}
	wire := proposalJSON(*proposal)
	return json.Marshal(wire)
}
