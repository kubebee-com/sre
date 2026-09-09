package orchestrator

import (
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/knowledge"
	"github.com/kubebee-com/sre/pkg/quality"
	"github.com/kubebee-com/sre/pkg/stewardship"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
	"strconv"
)

func (s *Server) adjudicate(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Adjudicate)
	if err != nil {
		respondError(w, err)
		return
	}
	var request stewardship.AdjudicateRequest
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	service := stewardship.Service{DB: s.config.DB, Policy: s.config.Policy}
	a, err := service.Adjudicate(r.Context(), principal(r), scope, request)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 201, a)
}
func (s *Server) adjudications(w http.ResponseWriter, r *http.Request) {
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
	var result []incident.Adjudication
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		var err error
		result, err = tx.Adjudications(incident.ItemRef{ID: r.PathValue("item"), Version: version}, 100)
		return err
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) corroborate(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Adjudicate)
	if err != nil {
		respondError(w, err)
		return
	}
	var request stewardship.CorroborateRequest
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	service := stewardship.Service{DB: s.config.DB, Policy: s.config.Policy}
	item, err := service.Corroborate(r.Context(), principal(r), scope, request)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 201, item)
}
func (s *Server) goldenCases(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	type view struct {
		Case     incident.GoldenCase `json:"case"`
		Eligible bool                `json:"eligible"`
	}
	result := []view{}
	err = s.config.DB.Transact(r.Context(), scope, func(tx *postgres.Tx) error {
		cases, err := tx.GoldenCases(r.URL.Query().Get("after"), 50)
		if err != nil {
			return err
		}
		for _, g := range cases {
			ok, err := knowledge.EligibleTx(tx, g)
			if err != nil {
				return err
			}
			result = append(result, view{g, ok})
		}
		return nil
	})
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) candidate(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.ReviewKnowledge)
	if err != nil {
		respondError(w, err)
		return
	}
	var request knowledge.CandidateRequest
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	service := knowledge.Service{DB: s.config.DB, Policy: s.config.Policy}
	g, err := service.Candidate(r.Context(), principal(r), scope, request)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 201, g)
}
func (s *Server) reviewGolden(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.ReviewKnowledge)
	if err != nil {
		respondError(w, err)
		return
	}
	var request struct {
		Version   int64  `json:"version"`
		Operation string `json:"operation"`
	}
	if decode(r, &request) != nil {
		respondError(w, postgres.ErrInvalid)
		return
	}
	service := knowledge.Service{DB: s.config.DB, Policy: s.config.Policy}
	var g incident.GoldenCase
	switch request.Operation {
	case "PUBLISH":
		g, err = service.Publish(r.Context(), principal(r), scope, r.PathValue("case"), request.Version)
	case "RETIRE":
		g, err = service.Retire(r.Context(), principal(r), scope, r.PathValue("case"), request.Version)
	default:
		err = postgres.ErrInvalid
	}
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, g)
}
func (s *Server) qualityMetrics(w http.ResponseWriter, r *http.Request) {
	scope, err := s.scope(r, authorization.Read)
	if err != nil {
		respondError(w, err)
		return
	}
	days := 30
	if r.URL.Query().Get("days") != "" {
		days, err = strconv.Atoi(r.URL.Query().Get("days"))
		if err != nil {
			respondError(w, postgres.ErrInvalid)
			return
		}
	}
	service := quality.Service{DB: s.config.DB, Policy: s.config.Policy}
	report, err := service.Report(r.Context(), principal(r), scope, days)
	if err != nil {
		respondError(w, err)
		return
	}
	writeJSON(w, 200, report)
}
