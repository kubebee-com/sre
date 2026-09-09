package orchestrator

import (
	"bytes"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/feedback"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"io"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) scopes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.config.Policy.Scopes(principal(r)))
}
func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"principal": principal(r), "csrf": r.Context().Value(csrfKey{}), "policy_version": s.config.Policy.Version()})
}
func (s *Server) incidents(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	var incidents []incident.Incident
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error { incidents, err = tx.Incidents(r.URL.Query().Get("after"), 50); return err })
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, incidents)
}

type itemView struct {
	Item     incident.Item            `json:"item"`
	Eligible bool                     `json:"eligible"`
	Feedback []incident.FeedbackEvent `json:"feedback"`
}

func (s *Server) items(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	views := []itemView{}
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		if _, err := tx.Incident(r.PathValue("incident")); err != nil {
			return err
		}
		items, err := tx.Items(r.PathValue("incident"), r.URL.Query().Get("after"), 50)
		if err != nil {
			return err
		}
		for _, item := range items {
			ref := incident.ItemRef{ID: item.ID, Version: item.Version}
			eligible, err := tx.Eligible(ref, time.Now())
			if err != nil {
				return err
			}
			events, err := tx.FeedbackHistory(ref, 20)
			if err != nil {
				return err
			}
			views = append(views, itemView{Item: item, Eligible: eligible, Feedback: events})
		}
		return nil
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, views)
}
func (s *Server) profiles(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Investigate)
	if err != nil {
		respondError(w, err)
		return
	}
	if s.config.Investigations == nil {
		writeJSON(w, 200, []string{})
		return
	}
	writeJSON(w, 200, s.config.Investigations.Profiles(scope))
}
func decode(r *http.Request, value any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return postgres.ErrInvalid
	}
	canonical, err := incident.CanonicalObject(raw)
	if err != nil {
		return postgres.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(canonical))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return postgres.ErrInvalid
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return postgres.ErrInvalid
	}
	return nil
}
func (s *Server) investigate(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Investigate)
	if err != nil {
		respondError(w, err)
		return
	}
	var request struct {
		ProfileID string `json:"profile_id"`
	}
	if err = decode(r, &request); err != nil {
		respondError(w, err)
		return
	}
	if s.config.Investigations == nil {
		respondError(w, postgres.ErrUnavailable)
		return
	}
	if s.config.Queue != nil {
		job, err := s.config.Queue.Enqueue(r.Context(), principal(r), scope, r.PathValue("incident"), request.ProfileID)
		if err != nil {
			respondError(w, err)
			return
		}
		writeJSON(w, 202, job)
		return
	}
	respondError(w, postgres.ErrUnavailable)
}
func (s *Server) submitFeedback(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Feedback)
	if err != nil {
		respondError(w, err)
		return
	}
	var request feedback.Request
	if err = decode(r, &request); err != nil {
		respondError(w, err)
		return
	}
	if request.IncidentID != r.PathValue("incident") {
		respondError(w, postgres.ErrInvalid)
		return
	}
	event, err := s.feedback.Submit(r.Context(), principal(r), scope, request)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 201, event)
}
func (s *Server) feedbackHistory(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	version, err := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
	if err != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	ref := incident.ItemRef{ID: r.PathValue("item"), Version: version}
	var events []incident.FeedbackEvent
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		item, err := tx.Item(ref)
		if err != nil {
			return err
		}
		if item.IncidentID != r.PathValue("incident") {
			return postgres.ErrNotFound
		}
		events, err = tx.FeedbackHistory(ref, 100)
		return err
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, events)
}
