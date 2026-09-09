package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type Assessment string

const (
	True         Assessment = "TRUE"
	False        Assessment = "FALSE"
	CannotVerify Assessment = "CANNOT_VERIFY"
)

type FeedbackEvent struct {
	Scope          identity.Scope `json:"scope"`
	IncidentID     string         `json:"incident_id"`
	ID             string         `json:"id"`
	ActorID        string         `json:"actor_id"`
	Item           ItemRef        `json:"item"`
	ItemHash       string         `json:"item_hash"`
	Assessment     Assessment     `json:"assessment"`
	ReasonCode     string         `json:"reason_code,omitempty"`
	Evidence       []ItemRef      `json:"evidence,omitempty"`
	Supersedes     string         `json:"supersedes,omitempty"`
	IdempotencyKey string         `json:"idempotency_key"`
	RequestHash    string         `json:"request_hash"`
	At             time.Time      `json:"at"`
}
