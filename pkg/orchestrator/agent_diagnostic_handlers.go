package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
	"time"
)

func (s *Server) diagnosticAgent(r *http.Request) (identity.Scope, investigation.AgentAuthenticator, error) {
	scope, err := agentScope(r)
	if err != nil {
		return scope, nil, postgres.ErrInvalid
	}
	if s.config.Fleet == nil || s.config.Queue == nil {
		return scope, nil, postgres.ErrUnavailable
	}
	token := agentToken(r)
	return scope, func(tx *postgres.Tx) (incident.Agent, error) {
		return s.config.Fleet.AuthenticateTx(tx, token, fleet.Collector)
	}, nil
}
func (s *Server) agentDiagnosticClaim(w http.ResponseWriter, r *http.Request) {
	scope, auth, err := s.diagnosticAgent(r)
	if err != nil {
		agentError(w, err)
		return
	}
	var req struct {
		Profiles []string `json:"profiles"`
	}
	if decode(r, &req) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	claim, err := s.config.Queue.ClaimAgent(r.Context(), scope, auth, req.Profiles)
	if err != nil {
		agentError(w, err)
		return
	}
	writeJSON(w, 200, claim)
}
func (s *Server) agentDiagnosticHeartbeat(w http.ResponseWriter, r *http.Request) {
	scope, auth, err := s.diagnosticAgent(r)
	if err != nil {
		agentError(w, err)
		return
	}
	var req struct {
		AttemptID string `json:"attempt_id"`
	}
	if decode(r, &req) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	until, err := s.config.Queue.HeartbeatAgent(r.Context(), scope, auth, r.PathValue("job"), req.AttemptID)
	if err != nil {
		agentError(w, err)
		return
	}
	writeJSON(w, 200, struct {
		LeaseUntil time.Time `json:"lease_until"`
	}{until})
}
func (s *Server) agentDiagnosticRefresh(w http.ResponseWriter, r *http.Request) {
	scope, auth, err := s.diagnosticAgent(r)
	if err != nil {
		agentError(w, err)
		return
	}
	var req struct {
		AttemptID string                `json:"attempt_id"`
		Checks    []investigation.Check `json:"checks"`
	}
	if decode(r, &req) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	state, err := s.config.Queue.RefreshAgent(r.Context(), scope, auth, r.PathValue("job"), req.AttemptID, req.Checks)
	if err != nil {
		agentError(w, err)
		return
	}
	writeJSON(w, 200, state)
}
func (s *Server) agentDiagnosticComplete(w http.ResponseWriter, r *http.Request) {
	scope, auth, err := s.diagnosticAgent(r)
	if err != nil {
		agentError(w, err)
		return
	}
	var req struct {
		AttemptID string                  `json:"attempt_id"`
		Result    investigation.RunResult `json:"result"`
	}
	if decode(r, &req) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	claim, err := s.config.Queue.CompleteAgent(r.Context(), scope, auth, r.PathValue("job"), req.AttemptID, req.Result)
	if err != nil {
		agentError(w, err)
		return
	}
	writeJSON(w, 200, incident.ItemRef{ID: claim.ID, Version: claim.Version})
}
