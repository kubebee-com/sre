package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
)

func (s *Server) diagnosticJobs(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	var result []incident.DiagnosticJob
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		var err error
		result, err = tx.DiagnosticJobs(r.PathValue("incident"))
		return err
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) cancelDiagnosticJob(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Investigate)
	if err != nil {
		respondError(w, err)
		return
	}
	if s.config.Queue == nil {
		respondError(w, postgres.ErrUnavailable)
		return
	}
	if err := s.config.Queue.Cancel(r.Context(), principal(r), scope, r.PathValue("job")); err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"state": "CANCELLED"})
}
