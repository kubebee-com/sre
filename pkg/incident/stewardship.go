package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type Adjudication struct {
	Scope              identity.Scope `json:"scope"`
	ID                 string         `json:"id"`
	IncidentID         string         `json:"incident_id"`
	Item               ItemRef        `json:"item"`
	ItemHash           string         `json:"item_hash"`
	FeedbackID         string         `json:"feedback_id,omitempty"`
	ActorID            string         `json:"actor_id"`
	Reason             string         `json:"reason"`
	CorrectionEvidence []ItemRef      `json:"correction_evidence"`
	RequestHash        string         `json:"request_hash"`
	IdempotencyKey     string         `json:"idempotency_key"`
	At                 time.Time      `json:"at"`
}
