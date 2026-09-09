package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
)

func (s *Server) reconcileAction(w http.ResponseWriter, r *http.Request) {
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
	a, err := s.config.Execution.Reconcile(r.Context(), principal(r), scope, r.PathValue("action"), request.Hash)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, a)
}
