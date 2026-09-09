package orchestrator

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/agent/collection"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"io"
	"net/http"
	"strings"
)

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Setup)
	if err != nil {
		respondError(w, err)
		return
	}
	if s.config.Fleet == nil {
		respondError(w, postgres.ErrUnavailable)
		return
	}
	var request struct {
		AgentID    string `json:"agent_id"`
		ClusterUID string `json:"cluster_uid"`
		Role       string `json:"role"`
	}
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	result, err := s.config.Fleet.Bootstrap(r.Context(), principal(r), scope, request.AgentID, request.ClusterUID, request.Role)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 201, result)
}
func agentScope(r *http.Request) (identity.Scope, error) {
	q := r.URL.Query()
	scope := identity.Scope{OrganizationID: q.Get("organization_id"), ClusterID: q.Get("cluster_id"), ApplicationID: q.Get("application_id")}
	return scope, scope.Validate()
}
func agentToken(r *http.Request) string {
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(headers[0], "Bearer ")
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if s.config.Fleet == nil {
		respondError(w, postgres.ErrUnavailable)
		return
	}
	scope, err := agentScope(r)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	var request struct {
		Token      string `json:"token"`
		ClusterUID string `json:"cluster_uid"`
		Role       string `json:"role"`
	}
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	credential, err := s.config.Fleet.Enroll(r.Context(), scope, request.Token, request.ClusterUID, request.Role)
	if err != nil {
		writeError(w, 401, "enrollment rejected")
		return
	}
	writeJSON(w, 201, credential)
}
func (s *Server) renewAgent(w http.ResponseWriter, r *http.Request) {
	if s.config.Fleet == nil {
		respondError(w, postgres.ErrUnavailable)
		return
	}
	scope, err := agentScope(r)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	var request struct {
		Role string `json:"role"`
	}
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	credential, err := s.config.Fleet.Renew(r.Context(), scope, agentToken(r), request.Role)
	if err != nil {
		writeError(w, 401, "agent credential rejected")
		return
	}
	writeJSON(w, 200, credential)
}
func (s *Server) collectReport(w http.ResponseWriter, r *http.Request) {
	if s.config.Fleet == nil {
		respondError(w, postgres.ErrUnavailable)
		return
	}
	scope, err := agentScope(r)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	var report collection.Report
	if collection.DecodeReport(raw, &report) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	service := collection.Service{Fleet: s.config.Fleet}
	if err := service.Ingest(r.Context(), scope, agentToken(r), report); err != nil {
		if err == fleet.ErrAgentUnauthorized {
			writeError(w, 401, "agent credential rejected")
		} else {
			respondError(w, err)
		}
		return
	}
	writeJSON(w, 202, map[string]string{"report_id": report.ID, "status": "RECORDED"})
}
func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Setup)
	if err != nil {
		respondError(w, err)
		return
	}
	if s.config.Fleet == nil {
		respondError(w, postgres.ErrUnavailable)
		return
	}
	if err := s.config.Fleet.Revoke(r.Context(), principal(r), scope, r.PathValue("agent")); err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, json.RawMessage(`{"revoked":true}`))
}

func (s *Server) setupScopes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.config.Policy.ScopesFor(principal(r), authorization.Setup))
}
func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		scope, err = s.scope(r, authorization.Setup)
	}
	if err != nil {
		respondError(w, err)
		return
	}
	var agents []incident.Agent
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error { var err error; agents, err = tx.Agents(); return err })
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, agents)
}

func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	scope, err := agentScope(r)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	allowed := []string{}
	for _, permission := range []authorization.Permission{authorization.Read, authorization.Investigate, authorization.Feedback, authorization.Approve, authorization.Adjudicate, authorization.ReviewKnowledge, authorization.Setup, authorization.SecurityPolicy} {
		if s.config.Policy.Authorize(principal(r), scope, permission) == nil {
			allowed = append(allowed, string(permission))
		}
	}
	writeJSON(w, 200, allowed)
}

func (s *Server) collectionChecks(w http.ResponseWriter, r *http.Request) {
	if s.config.Fleet == nil {
		respondError(w, postgres.ErrUnavailable)
		return
	}
	scope, err := agentScope(r)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	var requested bool
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		agent, err := s.config.Fleet.AuthenticateTx(tx, agentToken(r), fleet.Collector)
		if err != nil {
			return err
		}
		requested, err = tx.CollectionRequested(agent)
		return err
	})
	if err != nil {
		agentError(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"requested": requested})
}
