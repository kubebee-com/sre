package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
	"time"
)

func (s *Server) operations(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	var result postgres.OperationalSnapshot
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		var err error
		result, err = tx.OperationalSnapshot(time.Now().UTC())
		return err
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
