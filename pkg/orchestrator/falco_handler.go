package orchestrator

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/kubebee-com/sre/pkg/falco"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
)

// falcoWebhook processes incoming security alerts from Falco or Falcosidekick.
// It authenticates via token, applies privacy projection, and creates or updates
// incidents with sealed immutable evidence.
func (s *Server) falcoWebhook(w http.ResponseWriter, r *http.Request) {
	secret := s.config.FalcoSecret
	if secret == "" {
		secret = os.Getenv("SRE_FALCO_WEBHOOK_SECRET")
	}

	events, err := falco.ParseWebhookPayload(w, r, secret)
	if err != nil {
		switch {
		case errors.Is(err, falco.ErrUnauthorized):
			writeError(w, http.StatusUnauthorized, "invalid or missing webhook authentication token")
		case errors.Is(err, falco.ErrPayloadTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, "payload exceeds maximum limit")
		case errors.Is(err, falco.ErrInvalidJSON):
			writeError(w, http.StatusBadRequest, "invalid JSON payload")
		default:
			writeError(w, http.StatusBadRequest, "unable to process webhook: "+err.Error())
		}
		return
	}

	now := time.Now().UTC()
	processed := 0

	for _, ev := range events {
		if ev == nil {
			continue
		}

		orgID := r.URL.Query().Get("organization_id")
		if orgID == "" {
			orgID = "default"
		}
		clusterID := r.URL.Query().Get("cluster_id")
		if clusterID == "" {
			if ev.Hostname != "" && identity.ValidID(ev.Hostname) {
				clusterID = ev.Hostname
			} else {
				clusterID = "default"
			}
		}
		appID := r.URL.Query().Get("application_id")
		if appID == "" {
			ns := ev.Namespace()
			if ns != "" && identity.ValidID(ns) {
				appID = ns
			} else {
				appID = "default"
			}
		}

		scope := identity.Scope{
			OrganizationID: orgID,
			ClusterID:      clusterID,
			ApplicationID:  appID,
		}
		if err := scope.Validate(); err != nil {
			continue
		}

		bodyBytes, err := json.Marshal(ev)
		if err != nil {
			continue
		}

		canonicalBody, err := incident.CanonicalObject(bodyBytes)
		if err != nil {
			continue
		}

		if s.config.DB != nil {
			err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
				active, err := tx.ActiveIncident()
				incID := ""
				if err == nil && active.ID != "" {
					incID = active.ID
				} else {
					incID = identity.NewID()
					newInc := incident.Incident{
						Scope:    scope,
						ID:       incID,
						Version:  1,
						State:    "OPEN",
						OpenedAt: now,
					}
					if err := tx.CreateIncident(newInc); err != nil {
						return err
					}
				}

				item := incident.Item{
					Scope:      scope,
					IncidentID: incID,
					ID:         identity.NewID(),
					Version:    1,
					Kind:       incident.Evidence,
					Body:       canonicalBody,
					ObservedAt: now,
					ValidUntil: now.Add(24 * time.Hour),
				}
				if err := item.Seal(); err != nil {
					return err
				}
				return tx.PutItem(item)
			})
			if err == nil {
				processed++
			}
		} else {
			processed++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "accepted",
		"events_processed": processed,
	})
}
