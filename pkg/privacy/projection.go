// Package privacy projects source data before persistence or model inference.
package privacy

import (
	"encoding/hex"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/scanner"
	"math"
	"regexp"
	"time"
)

const Version = "strict-projection/v1"

type Code string

const (
	CrashLoop             Code = "CRASH_LOOP"
	PodFailed             Code = "POD_FAILED"
	DependencyUnavailable Code = "DEPENDENCY_UNAVAILABLE"
	NetworkBlocked        Code = "NETWORK_BLOCKED"
	ConfigurationDrift    Code = "CONFIGURATION_DRIFT"
	ResourcePressure      Code = "RESOURCE_PRESSURE"
	ReadUnavailable       Code = "READ_UNAVAILABLE"
	Healthy               Code = "HEALTHY"
	Unclassified          Code = "UNCLASSIFIED"
)

var ErrProjection = errors.New("observation does not satisfy strict privacy projection")

type Provenance struct {
	AgentID    string `json:"agent_id"`
	Generation int64  `json:"generation"`
	Epoch      string `json:"epoch"`
	ReportID   string `json:"report_id"`
}
type Target struct {
	Kind            string `json:"kind"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
	Commitment      string `json:"commitment"`
}
type Observation struct {
	Source            *Provenance        `json:"source,omitempty"`
	Target            *Target            `json:"target,omitempty"`
	Code              Code               `json:"code"`
	ResourceHandle    string             `json:"resource_handle"`
	DependencyHandles []string           `json:"dependency_handles,omitempty"`
	Metrics           map[string]float64 `json:"metrics,omitempty"`
	ObservedAt        time.Time          `json:"observed_at"`
	ValidUntil        time.Time          `json:"valid_until"`
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidUID(uid string) bool { return uuidPattern.MatchString(uid) }

func ValidHandle(handle string) bool {
	if len(handle) != 32 {
		return false
	}
	_, err := hex.DecodeString(handle)
	return err == nil
}
func (o Observation) Validate() error {
	if o.Source != nil {
		s := o.Source
		if !identity.ValidID(s.AgentID) || s.Generation < 1 || !identity.ValidID(s.Epoch) || !ValidHandle(s.ReportID) {
			return ErrProjection
		}
	}
	if o.Target != nil {
		t := o.Target
		if t.Kind != "Pod" && t.Kind != "Deployment" && t.Kind != "Service" && t.Kind != "StatefulSet" && t.Kind != "Node" && t.Kind != "Unknown" {
			return ErrProjection
		}
		if t.UID != "" && !ValidUID(t.UID) {
			return ErrProjection
		}
		if len(t.ResourceVersion) > 64 {
			return ErrProjection
		}
		for _, r := range t.ResourceVersion {
			if r < '0' || r > '9' {
				return ErrProjection
			}
		}
		if len(t.Commitment) != 64 {
			return ErrProjection
		}
		if _, err := hex.DecodeString(t.Commitment); err != nil {
			return ErrProjection
		}
	}

	switch o.Code {
	case CrashLoop, PodFailed, DependencyUnavailable, NetworkBlocked, ConfigurationDrift, ResourcePressure, ReadUnavailable, Healthy, Unclassified:
	default:
		return ErrProjection
	}
	if !ValidHandle(o.ResourceHandle) || o.ObservedAt.IsZero() || !o.ValidUntil.After(o.ObservedAt) || o.ValidUntil.Sub(o.ObservedAt) > time.Hour || len(o.DependencyHandles) > 32 || len(o.Metrics) > 8 {
		return ErrProjection
	}
	for _, handle := range o.DependencyHandles {
		if !ValidHandle(handle) {
			return ErrProjection
		}
	}
	for name, value := range o.Metrics {
		switch name {
		case "restart_count", "ready_replicas", "desired_replicas", "memory_usage_ratio", "cpu_usage_ratio", "error_ratio", "latency_ms":
		default:
			return ErrProjection
		}
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1e15 {
			return ErrProjection
		}
	}
	return nil
}
func ProjectIssue(raw scanner.Issue, handle string, at time.Time, ttl time.Duration) (Observation, error) {
	code := Unclassified
	switch raw.Category {
	case scanner.CategoryCrashLoop:
		code = CrashLoop
	case scanner.CategoryPodFailed:
		code = PodFailed
	}
	// Deliberately exclude logs, specs, summaries, names, events and annotations.
	projected := Observation{Code: code, ResourceHandle: handle, ObservedAt: at.UTC(), ValidUntil: at.Add(ttl).UTC()}
	return projected, projected.Validate()
}
