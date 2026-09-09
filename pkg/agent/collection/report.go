package collection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/recovery"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"io"
	"time"
)

type Report struct {
	ID           string                `json:"id"`
	ClusterUID   string                `json:"cluster_uid"`
	ObservedAt   time.Time             `json:"observed_at"`
	Coverage     string                `json:"coverage"`
	Observations []privacy.Observation `json:"observations"`
}

func (r Report) Validate() error {
	if !privacy.ValidHandle(r.ID) || !identity.ValidID(r.ClusterUID) || r.ObservedAt.IsZero() || r.ObservedAt.After(time.Now().Add(30*time.Second)) || time.Since(r.ObservedAt) > 5*time.Minute || len(r.Observations) > 50 {
		return postgres.ErrInvalid
	}
	if r.Coverage != "COMPLETE" && r.Coverage != "PARTIAL" && r.Coverage != "UNAVAILABLE" {
		return postgres.ErrInvalid
	}
	seen := make(map[string]bool)
	for _, o := range r.Observations {
		key := o.ResourceHandle + "/" + string(o.Code)
		if seen[key] || o.ObservedAt.Before(r.ObservedAt.Add(-5*time.Minute)) || o.ObservedAt.After(r.ObservedAt.Add(30*time.Second)) {
			return postgres.ErrInvalid
		}
		seen[key] = true
		if o.Validate() != nil || o.Source != nil || o.ObservedAt.After(time.Now().Add(30*time.Second)) || !o.ValidUntil.After(time.Now()) {
			return postgres.ErrInvalid
		}
	}
	return nil
}
func DecodeReport(raw []byte, report *Report) error {
	if _, err := incident.CanonicalObject(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(report) != nil {
		return postgres.ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return postgres.ErrInvalid
	}
	return report.Validate()
}

type Service struct{ Fleet *fleet.Service }

func (s *Service) Ingest(ctx context.Context, scope identity.Scope, token string, report Report) error {
	if report.Validate() != nil {
		return postgres.ErrInvalid
	}
	return s.Fleet.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		agent, err := s.Fleet.AuthenticateTx(tx, token, fleet.Collector)
		if err != nil {
			return err
		}
		if agent.ClusterUID != report.ClusterUID {
			return fleet.ErrAgentUnauthorized
		}
		raw, _ := json.Marshal(report)
		digest := sha256.Sum256(raw)
		payload, _ := json.Marshal(map[string]string{"report_hash": hex.EncodeToString(digest[:])})
		created, err := tx.EnqueueOnce(report.ID, "COLLECTOR_REPORT", payload)
		if err != nil || !created {
			return err
		}
		if err := tx.PutCoverage(agent, report.Coverage, report.ObservedAt); err != nil {
			return err
		}
		episode, episodeErr := tx.ActiveIncident()
		incidentID := episode.ID
		if errors.Is(episodeErr, postgres.ErrNotFound) {
			hasFinding := false
			for _, o := range report.Observations {
				if o.Code != privacy.Healthy && o.Code != privacy.ReadUnavailable {
					hasFinding = true
				}
			}
			if !hasFinding {
				return nil
			}
			incidentID = identity.NewID()
		} else if episodeErr != nil {
			return episodeErr
		}
		for _, observation := range report.Observations {
			digest := sha256.Sum256([]byte(scope.Key() + "/" + incidentID + "/" + observation.ResourceHandle + "/" + string(observation.Code)))
			id := hex.EncodeToString(digest[:])
			_, err := tx.Incident(incidentID)
			if errors.Is(err, postgres.ErrNotFound) {
				if err = tx.CreateIncident(incident.Incident{Scope: scope, ID: incidentID, Version: 1, State: "OPEN", OpenedAt: report.ObservedAt}); err != nil {
					return err
				}
				summary, _ := json.Marshal(map[string]string{"incident_id": incidentID})
				if err = tx.Enqueue(incidentID, "INCIDENT_CREATED", summary); err != nil {
					return err
				}
			} else if err != nil {
				return err
			}
			current, err := tx.CurrentItem(id)
			version := int64(1)
			if err == nil {
				if !observation.ObservedAt.After(current.ObservedAt) {
					continue
				}
				version = current.Version + 1
			} else if !errors.Is(err, postgres.ErrNotFound) {
				return err
			}
			if err := tx.FulfillCollectionChecks(agent, observation.ResourceHandle, observation.ObservedAt); err != nil {
				return err
			}
			observation.Source = &privacy.Provenance{AgentID: agent.ID, Generation: agent.Generation, Epoch: agent.Epoch, ReportID: report.ID}
			body, _ := json.Marshal(observation)
			if err = tx.PutItem(incident.Item{Scope: scope, IncidentID: incidentID, ID: id, Version: version, Kind: incident.Evidence, Body: body, ObservedAt: observation.ObservedAt, ValidUntil: observation.ValidUntil}); err != nil {
				return err
			}
			if observation.Target != nil && observation.Target.Kind == "Deployment" {
				sample := incident.HealthSample{Scope: scope, IncidentID: incidentID, Evidence: incident.ItemRef{ID: id, Version: version}, Handle: observation.ResourceHandle, UID: observation.Target.UID, AgentID: agent.ID, Generation: agent.Generation, Epoch: agent.Epoch, Coverage: report.Coverage, Healthy: observation.Code == privacy.Healthy, ReadyReplicas: int(observation.Metrics["ready_replicas"]), At: observation.ObservedAt}
				if err := tx.PutHealthSample(sample); err != nil {
					return err
				}
			}
		}

		if _, err := tx.RecoveryProfile("application-health"); err == nil {
			assessment, err := recovery.AssessTx(tx, scope, incidentID, "application-health", time.Now().UTC())
			if err != nil {
				return err
			}
			current, err := tx.Incident(incidentID)
			if err != nil {
				return err
			}
			if assessment.Status == "RECOVERED" && current.State != "RECOVERED" {
				if err := tx.UpdateIncident(incidentID, current.Version, "RECOVERED"); err != nil {
					return err
				}
				payload, _ := json.Marshal(map[string]string{"incident_id": incidentID, "status": "RECOVERED"})
				return tx.Enqueue(identity.NewID(), "RECOVERY_CHANGED", payload)
			}
			if assessment.Status != "RECOVERED" && current.State == "RECOVERED" {
				if err := tx.UpdateIncident(incidentID, current.Version, "OPEN"); err != nil {
					return err
				}
				payload, _ := json.Marshal(map[string]string{"incident_id": incidentID, "status": assessment.Status})
				return tx.Enqueue(identity.NewID(), "RECOVERY_CHANGED", payload)
			}
		} else if !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
		return nil
	})
}
