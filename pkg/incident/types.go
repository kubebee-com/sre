// Package incident keeps observations distinct from diagnostic assertions.
package incident

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type ItemKind string

const (
	Evidence ItemKind = "EVIDENCE"
	Claim    ItemKind = "CLAIM"
)

type ItemRef struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}
type Item struct {
	Scope      identity.Scope  `json:"scope"`
	IncidentID string          `json:"incident_id"`
	ID         string          `json:"id"`
	Version    int64           `json:"version"`
	Kind       ItemKind        `json:"kind"`
	Body       json.RawMessage `json:"body"`
	ObservedAt time.Time       `json:"observed_at"`
	ValidUntil time.Time       `json:"valid_until"`
	Parents    []ItemRef       `json:"parents"`
	Hash       string          `json:"hash,omitempty"`
}
type Incident struct {
	Scope    identity.Scope `json:"scope"`
	ID       string         `json:"id"`
	Version  int64          `json:"version"`
	State    string         `json:"state"`
	OpenedAt time.Time      `json:"opened_at"`
}

// Raw names stay in the encrypted local agent registry. This identity cannot
// resolve a Kubernetes target without that registry and its current authority.
type ResourceIdentity struct {
	Scope                identity.Scope `json:"scope"`
	APIGroup             string         `json:"api_group"`
	Kind                 string         `json:"kind"`
	Handle               string         `json:"handle"`
	UID                  string         `json:"uid"`
	TargetCommitment     string         `json:"target_commitment"`
	AuthorityEpoch       string         `json:"authority_epoch"`
	EnrollmentGeneration int64          `json:"enrollment_generation"`
}
