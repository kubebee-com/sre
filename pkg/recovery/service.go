// Package recovery evaluates independent observed health, never action receipts.
package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"sort"
	"time"
)

func ValidateProfile(p incident.RecoveryProfile) error {
	if p.Scope.Validate() != nil || !identity.ValidID(p.ID) || p.Version < 1 || len(p.Handles) < 1 || len(p.Handles) > 16 || p.WindowSeconds < 60 || p.WindowSeconds > 3600 || p.MaximumGapSeconds < 15 || p.MaximumGapSeconds > 120 || p.MinimumSamples < 3 || p.MinimumSamples > 100 || p.MinimumReadyReplicas < 1 || p.MinimumReadyReplicas > 100000 {
		return postgres.ErrInvalid
	}
	seen := map[string]bool{}
	for _, h := range p.Handles {
		if !privacy.ValidHandle(h) || seen[h] {
			return postgres.ErrInvalid
		}
		seen[h] = true
	}
	return nil
}

// AssessWindow consumes samples in reverse time order and stops at the first
// incomplete, unhealthy, discontinuous or different source observation.
func AssessWindow(p incident.RecoveryProfile, samples []incident.HealthSample, at time.Time) (string, string) {
	if len(samples) == 0 {
		return "UNKNOWN", "MISSING_OBSERVATIONS"
	}
	head := samples[0]
	gap := time.Duration(p.MaximumGapSeconds) * time.Second
	if head.At.After(at) || at.Sub(head.At) > gap {
		return "UNKNOWN", "STALE_OBSERVATIONS"
	}
	previous := at
	for n, s := range samples {
		if s.At.After(previous) || previous.Sub(s.At) > gap {
			return "UNKNOWN", "OBSERVATION_GAP"
		}
		if s.Coverage != "COMPLETE" {
			return "UNKNOWN", "INCOMPLETE_COVERAGE"
		}
		if s.UID != head.UID || s.AgentID != head.AgentID || s.Generation != head.Generation || s.Epoch != head.Epoch {
			return "UNKNOWN", "SOURCE_CHANGED"
		}
		if !s.Healthy || s.ReadyReplicas < p.MinimumReadyReplicas {
			return "NOT_RECOVERED", "HEALTH_REQUIREMENT_FAILED"
		}
		if n+1 >= p.MinimumSamples && head.At.Sub(s.At) >= time.Duration(p.WindowSeconds)*time.Second {
			return "RECOVERED", "SUSTAINED_OBSERVED_HEALTH"
		}
		previous = s.At
	}
	return "UNKNOWN", "WINDOW_INCOMPLETE"
}

type Service struct {
	DB     *postgres.Store
	Policy *authorization.Policy
}

func (s *Service) SetProfile(ctx context.Context, p identity.Principal, profile incident.RecoveryProfile) (incident.RecoveryProfile, error) {
	if err := s.Policy.Authorize(p, profile.Scope, authorization.Setup); err != nil {
		return profile, err
	}
	if ValidateProfile(profile) != nil {
		return profile, postgres.ErrInvalid
	}
	profile.Handles = append([]string(nil), profile.Handles...)
	sort.Strings(profile.Handles)
	err := s.DB.Transact(ctx, profile.Scope, func(tx *postgres.Tx) error {
		old, err := tx.RecoveryProfile(profile.ID)
		if err == nil {
			if profile.Version != old.Version+1 {
				return postgres.ErrConflict
			}
		} else if !errors.Is(err, postgres.ErrNotFound) {
			return err
		} else if profile.Version != 1 {
			return postgres.ErrConflict
		}
		return tx.PutRecoveryProfile(profile)
	})
	return profile, err
}
func (s *Service) Assess(ctx context.Context, p identity.Principal, scope identity.Scope, incidentID, profileID string) (incident.RecoveryAssessment, error) {
	if err := s.Policy.Authorize(p, scope, authorization.Read); err != nil {
		return incident.RecoveryAssessment{}, err
	}
	var a incident.RecoveryAssessment
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		var err error
		a, err = AssessTx(tx, scope, incidentID, profileID, time.Now().UTC())
		return err
	})
	return a, err
}
func AssessTx(tx *postgres.Tx, scope identity.Scope, incidentID, profileID string, at time.Time) (incident.RecoveryAssessment, error) {
	p, err := tx.RecoveryProfile(profileID)
	if err != nil {
		return incident.RecoveryAssessment{}, err
	}
	if ValidateProfile(p) != nil {
		return incident.RecoveryAssessment{}, postgres.ErrInvalid
	}
	a := incident.RecoveryAssessment{ID: identity.NewID(), Scope: scope, IncidentID: incidentID, ProfileID: p.ID, ProfileVersion: p.Version, Status: "RECOVERED", Reason: "SUSTAINED_OBSERVED_HEALTH", At: at, Evidence: []incident.ItemRef{}}
	for _, h := range p.Handles {
		samples, err := tx.HealthSamples(incidentID, h, at.Add(-time.Duration(p.WindowSeconds+p.MaximumGapSeconds*2)*time.Second))
		if err != nil {
			return a, err
		}
		status, reason := AssessWindow(p, samples, at)
		if status != "RECOVERED" {
			a.Status = status
			a.Reason = reason
			break
		}
		// Historic samples establish duration; the newest sample must still have
		// current collector authority and freshness at the assessment boundary.
		eligible, err := tx.Eligible(samples[0].Evidence, at)
		if err != nil {
			return a, err
		}
		if !eligible {
			a.Status = "UNKNOWN"
			a.Reason = "SOURCE_NOT_ELIGIBLE"
			break
		}
		for n, sample := range samples {
			ok, err := tx.Uncontested(sample.Evidence)
			if err != nil {
				return a, err
			}
			if !ok {
				a.Status = "UNKNOWN"
				a.Reason = "DISPUTED_HEALTH_EVIDENCE"
				break
			}
			a.Evidence = append(a.Evidence, sample.Evidence)
			if n+1 >= p.MinimumSamples && samples[0].At.Sub(sample.At) >= time.Duration(p.WindowSeconds)*time.Second {
				break
			}
		}
		if a.Status != "RECOVERED" {
			break
		}
	}
	if err := tx.PutRecoveryAssessment(a); err != nil {
		return a, err
	}
	payload, _ := json.Marshal(map[string]string{"incident_id": incidentID, "assessment_id": a.ID, "status": a.Status})
	if err := tx.Enqueue(a.ID, "RECOVERY_ASSESSED", payload); err != nil {
		return a, err
	}
	return a, nil
}
