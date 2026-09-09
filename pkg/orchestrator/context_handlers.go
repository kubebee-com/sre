package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/environment"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
)

func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		scope, err = s.scope(r, authorization.Setup)
	}
	if err != nil {
		respondError(w, err)
		return
	}
	var c incident.EnvironmentContext
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error { var err error; c, err = tx.EnvironmentContext(); return err })
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, c)
}
func (s *Server) setEnvironment(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Setup)
	if err != nil {
		respondError(w, err)
		return
	}
	var c incident.EnvironmentContext
	if decode(r, &c) != nil || c.Scope != scope {
		respondError(w, postgres.ErrInvalid)
		return
	}
	service := environment.Service{DB: s.config.DB, Policy: s.config.Policy}
	if err := service.Set(r.Context(), principal(r), c); err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 201, c)
}
