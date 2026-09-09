package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/delivery"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
)

func (s *Server) notifications(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	var result []incident.Notification
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		var err error
		result, err = tx.Notifications(r.URL.Query().Get("after"), 50)
		return err
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) acknowledgeNotification(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Approve)
	if err != nil {
		respondError(w, err)
		return
	}
	service := delivery.Service{DB: s.config.DB, Policy: s.config.Policy}
	if err := service.Acknowledge(r.Context(), principal(r), scope, r.PathValue("notification")); err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"acknowledged": true})
}
