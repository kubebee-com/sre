package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/recovery"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
	"time"
)

func (s *Server) setRecoveryProfile(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Setup)
	if err != nil {
		respondError(w, err)
		return
	}
	var p incident.RecoveryProfile
	if decode(r, &p) != nil || p.Scope != scope || p.ID != "application-health" {
		respondError(w, postgres.ErrInvalid)
		return
	}
	service := recovery.Service{DB: s.config.DB, Policy: s.config.Policy}
	p, err = service.SetProfile(r.Context(), principal(r), p)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 201, p)
}
func (s *Server) getRecoveryProfile(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	var p incident.RecoveryProfile
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		var err error
		p, err = tx.RecoveryProfile("application-health")
		return err
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, p)
}
func (s *Server) assessRecovery(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	service := recovery.Service{DB: s.config.DB, Policy: s.config.Policy}
	a, err := service.Assess(r.Context(), principal(r), scope, r.PathValue("incident"), "application-health")
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, a)
}
func (s *Server) closeIncident(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Approve)
	if err != nil {
		respondError(w, err)
		return
	}
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		id := r.PathValue("incident")
		current, err := tx.Incident(id)
		if err != nil {
			return err
		}
		a, err := recovery.AssessTx(tx, scope, id, "application-health", time.Now().UTC())
		if err != nil {
			return err
		}
		if a.Status != "RECOVERED" {
			return postgres.ErrConflict
		}
		return tx.UpdateIncident(id, current.Version, "CLOSED")
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"state": "CLOSED"})
}
