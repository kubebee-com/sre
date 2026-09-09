package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

// RecoveryProfile defines independent sustained health requirements.
type RecoveryProfile struct {
	Scope                identity.Scope `json:"scope"`
	ID                   string         `json:"id"`
	Version              int64          `json:"version"`
	Handles              []string       `json:"handles"`
	WindowSeconds        int            `json:"window_seconds"`
	MaximumGapSeconds    int            `json:"maximum_gap_seconds"`
	MinimumSamples       int            `json:"minimum_samples"`
	MinimumReadyReplicas int            `json:"minimum_ready_replicas"`
}
type HealthSample struct {
	Scope         identity.Scope `json:"scope"`
	IncidentID    string         `json:"incident_id"`
	Evidence      ItemRef        `json:"evidence"`
	Handle        string         `json:"handle"`
	UID           string         `json:"uid"`
	AgentID       string         `json:"agent_id"`
	Generation    int64          `json:"generation"`
	Epoch         string         `json:"epoch"`
	Coverage      string         `json:"coverage"`
	Healthy       bool           `json:"healthy"`
	ReadyReplicas int            `json:"ready_replicas"`
	At            time.Time      `json:"at"`
}
type RecoveryAssessment struct {
	ID             string         `json:"id"`
	Scope          identity.Scope `json:"scope"`
	IncidentID     string         `json:"incident_id"`
	ProfileID      string         `json:"profile_id"`
	ProfileVersion int64          `json:"profile_version"`
	Status         string         `json:"status"`
	Reason         string         `json:"reason"`
	Evidence       []ItemRef      `json:"evidence"`
	At             time.Time      `json:"at"`
}
