package incident

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type ActionPlan struct {
	Scope              identity.Scope `json:"scope"`
	ID                 string         `json:"id"`
	IncidentID         string         `json:"incident_id"`
	Kind               string         `json:"kind"`
	Evidence           ItemRef        `json:"evidence"`
	EvidenceHash       string         `json:"evidence_hash"`
	ResourceHandle     string         `json:"resource_handle"`
	TargetCommitment   string         `json:"target_commitment"`
	SourceAgentID      string         `json:"source_agent_id"`
	SourceGeneration   int64          `json:"source_generation"`
	ExecutorID         string         `json:"executor_id"`
	ExecutorGeneration int64          `json:"executor_generation"`
	Epoch              string         `json:"epoch"`
	PolicyVersion      string         `json:"policy_version"`
	ExpiresAt          time.Time      `json:"expires_at"`
}

func (p ActionPlan) Hash() string {
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type Action struct {
	Plan              ActionPlan `json:"plan"`
	Hash              string     `json:"hash"`
	Version           int64      `json:"version"`
	State             string     `json:"state"`
	ProposedBy        string     `json:"proposed_by"`
	ApprovedBy        string     `json:"approved_by,omitempty"`
	ApprovalExpiresAt time.Time  `json:"approval_expires_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	SubmittedAt       time.Time  `json:"submitted_at,omitempty"`
	CompletedAt       time.Time  `json:"completed_at,omitempty"`
	OutcomeCode       string     `json:"outcome_code,omitempty"`
	ReconciledBy      string     `json:"reconciled_by,omitempty"`
}
