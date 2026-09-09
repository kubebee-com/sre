package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type Agent struct {
	Scope      identity.Scope `json:"scope"`
	ID         string         `json:"id"`
	Role       string         `json:"role"`
	Audience   string         `json:"audience"`
	Epoch      string         `json:"epoch"`
	Generation int64          `json:"generation"`
	ClusterUID string         `json:"cluster_uid"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Revoked    bool           `json:"revoked"`
}
type AgentBootstrap struct {
	Agent     Agent
	TokenHash string
	ExpiresAt time.Time
}
