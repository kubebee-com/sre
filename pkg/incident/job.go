package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type DiagnosticJob struct {
	Scope      identity.Scope `json:"scope"`
	ID         string         `json:"id"`
	IncidentID string         `json:"incident_id"`
	ProfileID  string         `json:"profile_id"`
	ActorID    string         `json:"actor_id"`
	State      string         `json:"state"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Result     *ItemRef       `json:"result,omitempty"`
}
