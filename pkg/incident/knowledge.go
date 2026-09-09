package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type KnowledgeEvaluation struct {
	Version       string `json:"version"`
	BaselineCases int    `json:"baseline_cases"`
	HeldoutCases  int    `json:"heldout_cases"`
	Passed        int    `json:"passed"`
	Approved      bool   `json:"approved"`
}
type GoldenCase struct {
	Scope       identity.Scope      `json:"scope"`
	ID          string              `json:"id"`
	Version     int64               `json:"version"`
	State       string              `json:"state"`
	IncidentID  string              `json:"incident_id"`
	Claim       ItemRef             `json:"claim"`
	ClaimHash   string              `json:"claim_hash"`
	RecoveryID  string              `json:"recovery_id"`
	CauseCode   string              `json:"cause_code"`
	CreatedBy   string              `json:"created_by"`
	ReviewedBy  string              `json:"reviewed_by,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	PublishedAt time.Time           `json:"published_at,omitempty"`
	Evaluation  KnowledgeEvaluation `json:"evaluation"`
}
