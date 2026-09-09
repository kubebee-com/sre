package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/interaction"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
)

func (s *Server) interactions(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	var result []interaction.Request
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		var err error
		result, err = tx.Interactions(r.URL.Query().Get("after"), 50)
		return err
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) createInteraction(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Investigate)
	if err != nil {
		respondError(w, err)
		return
	}
	var request interaction.Request
	if decode(r, &request) != nil || request.Scope != scope {
		respondError(w, postgres.ErrInvalid)
		return
	}
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error { return tx.CreateInteraction(request, principal(r).ID) })
	if err != nil {
		respondError(w, err)
		return
	}
	request.CreatedBy = principal(r).ID
	writeJSON(w, 201, request)
}
func (s *Server) answerInteraction(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Investigate)
	if err != nil {
		respondError(w, err)
		return
	}
	var request struct {
		Version int64  `json:"version"`
		Answer  string `json:"answer"`
	}
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		return tx.AnswerInteraction(r.PathValue("request"), request.Version, request.Answer, principal(r).ID)
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"answered": true})
}

func (s *Server) registerInteractionRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/interactions", s.interactions)
	mux.HandleFunc("POST /api/interactions", s.createInteraction)
	mux.HandleFunc("POST /api/interactions/{request}/answer", s.answerInteraction)
}
