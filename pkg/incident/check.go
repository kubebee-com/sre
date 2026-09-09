package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type CollectionCheck struct {
	Scope      identity.Scope `json:"scope"`
	ID         string         `json:"id"`
	IncidentID string         `json:"incident_id"`
	AgentID    string         `json:"agent_id"`
	Generation int64          `json:"generation"`
	Handle     string         `json:"handle"`
	Kind       string         `json:"kind"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
}
