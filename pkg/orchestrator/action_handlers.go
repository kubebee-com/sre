package orchestrator

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
)

func (s *Server) listActions(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	var result []incident.Action
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		var err error
		result, err = tx.Actions(r.URL.Query().Get("after"), 50)
		return err
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) proposeAction(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Investigate)
	if err != nil {
		respondError(w, err)
		return
	}
	var request execution.ProposeRequest
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	a, err := s.config.Execution.Propose(r.Context(), principal(r), scope, request)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 201, a)
}
func (s *Server) approveAction(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Approve)
	if err != nil {
		respondError(w, err)
		return
	}
	var request struct {
		Hash string `json:"hash"`
	}
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	a, err := s.config.Execution.Approve(r.Context(), principal(r), scope, r.PathValue("action"), request.Hash)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, a)
}
func (s *Server) cancelAction(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Approve)
	if err != nil {
		respondError(w, err)
		return
	}
	a, err := s.config.Execution.Cancel(r.Context(), principal(r), scope, r.PathValue("action"))
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, a)
}
func (s *Server) executorActions(w http.ResponseWriter, r *http.Request) {
	if s.config.Execution == nil || !s.config.Execution.Enabled || s.config.Fleet == nil {
		respondError(w, authorization.ErrForbidden)
		return
	}
	scope, err := agentScope(r)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	result := []incident.Action{}
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		agent, err := s.config.Fleet.AuthenticateTx(tx, agentToken(r), fleet.Executor)
		if err != nil {
			return err
		}
		actions, err := tx.ExecutorActions(agent, r.URL.Query().Get("after"), 100)
		if err != nil {
			return err
		}
		bytes := 2
		for _, a := range actions {
			if a.Plan.ExecutorID == agent.ID && a.Plan.ExecutorGeneration == agent.Generation && a.State == "APPROVED" {
				encoded, err := json.Marshal(a)
				if err != nil {
					return postgres.ErrInvalid
				}
				if bytes+len(encoded)+1 > 60000 {
					break
				}
				bytes += len(encoded) + 1
				result = append(result, a)
			}
		}
		return nil
	})
	if err != nil {
		agentError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) claimAction(w http.ResponseWriter, r *http.Request) {
	scope, err := agentScope(r)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	claim, err := s.config.Execution.Claim(r.Context(), scope, agentToken(r), r.PathValue("action"))
	if err != nil {
		agentError(w, err)
		return
	}
	writeJSON(w, 200, claim)
}
func (s *Server) actionReceipt(w http.ResponseWriter, r *http.Request) {
	scope, err := agentScope(r)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	var request struct {
		ReceiptToken string `json:"receipt_token"`
		Outcome      string `json:"outcome"`
	}
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	a, err := s.config.Execution.Receipt(r.Context(), scope, agentToken(r), r.PathValue("action"), request.ReceiptToken, request.Outcome)
	if err != nil {
		agentError(w, err)
		return
	}
	writeJSON(w, 200, a)
}
func agentError(w http.ResponseWriter, err error) {
	if err == fleet.ErrAgentUnauthorized {
		writeError(w, 401, "agent credential rejected")
		return
	}
	respondError(w, err)
}
