package legacyserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/kubebee-com/sre/pkg/playbook"
)

func (s *Server) PlaybookService() *playbook.Service { return s.playbooks }
func (s *Server) playbookAvailable(w http.ResponseWriter) bool {
	if s.playbooks == nil {
		s.writeError(w, http.StatusServiceUnavailable, "playbook catalog is not configured")
		return false
	}
	return true
}
func (s *Server) playbookError(w http.ResponseWriter, err error) {
	status, message := http.StatusServiceUnavailable, "playbook operation unavailable"
	switch {
	case errors.Is(err, playbook.ErrServiceTaskFailed):
		status, message = http.StatusBadGateway, "playbook provider task failed; retry later"
	case errors.Is(err, playbook.ErrCatalogNotFound):
		status, message = http.StatusNotFound, "playbook record not found"
	case errors.Is(err, playbook.ErrInvalidTransition), errors.Is(err, playbook.ErrCatalogConflict):
		status, message = http.StatusConflict, "playbook state or version conflicts"
	case errors.Is(err, playbook.ErrServiceGuardrail):
		status, message = http.StatusUnprocessableEntity, "playbook guardrails blocked this operation"
	case errors.Is(err, playbook.ErrServiceInvalid), errors.Is(err, playbook.ErrCatalogInvalid):
		status, message = http.StatusBadRequest, "invalid playbook request or policy change"
	case errors.Is(err, context.DeadlineExceeded):
		status, message = http.StatusGatewayTimeout, "playbook operation timed out"
	}
	s.writeError(w, status, message)
}
func decodePlaybookJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	if !requireJSONContentType(w, r) {
		return false
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeDecodeError(w, err)
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			writeError(w, http.StatusBadRequest, "invalid request payload")
		} else {
			writeDecodeError(w, err)
		}
		return false
	}
	return true
}
func (s *Server) handlePlaybookList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.playbookAvailable(w) {
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > playbook.MaxCollectionItems {
			s.writeError(w, http.StatusBadRequest, "limit must be between 1 and 256")
			return
		}
		limit = value
	}
	rows, err := s.playbooks.List(r.Context(), limit)
	if err != nil {
		s.playbookError(w, err)
		return
	}
	if rows == nil {
		rows = []playbook.NormalizedPlaybook{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"playbooks": rows, "limit": limit})
}
func (s *Server) handlePlaybookImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.playbookAvailable(w) {
		return
	}
	var req playbook.ImportRequest
	if !decodePlaybookJSON(w, r, &req) {
		return
	}
	actor := requestActor(s, r)
	if actor == "" {
		s.writeError(w, http.StatusUnauthorized, "authenticated actor is required")
		return
	}
	result, err := s.playbooks.Import(r.Context(), req, actor)
	if err != nil {
		s.playbookError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}
func (s *Server) handlePlaybookTransition(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.playbookAvailable(w) {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/playbooks/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		s.writeError(w, http.StatusNotFound, "playbook action not found")
		return
	}
	states := map[string]playbook.LifecycleState{"review": playbook.LifecycleReview, "approve": playbook.LifecycleActive, "reject": playbook.LifecycleRejected, "retire": playbook.LifecycleRetired}
	state, ok := states[parts[1]]
	if !ok {
		s.writeError(w, http.StatusNotFound, "playbook action not found")
		return
	}
	var req struct {
		Version int `json:"version"`
	}
	if !decodePlaybookJSON(w, r, &req) {
		return
	}
	if req.Version < 1 {
		s.writeError(w, http.StatusBadRequest, "playbook version must be positive")
		return
	}
	actor := requestActor(s, r)
	if actor == "" {
		s.writeError(w, http.StatusUnauthorized, "authenticated actor is required")
		return
	}
	if err := s.playbooks.Transition(r.Context(), parts[0], req.Version, state, actor); err != nil {
		s.playbookError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"id": parts[0], "version": req.Version, "lifecycle": state})
}
func (s *Server) handlePlaybookSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.playbookAvailable(w) {
		return
	}
	if r.Method == http.MethodPut {
		var settings playbook.ServiceSettings
		if !decodePlaybookJSON(w, r, &settings) {
			return
		}
		actor := requestActor(s, r)
		if actor == "" {
			s.writeError(w, http.StatusUnauthorized, "authenticated actor is required")
			return
		}
		if err := s.playbooks.UpdateSettings(settings, actor); err != nil {
			s.playbookError(w, err)
			return
		}
	}
	s.writeJSON(w, http.StatusOK, s.playbooks.Settings())
}
func (s *Server) handlePlaybookStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	status := playbook.ServiceStatus{Reason: "playbook catalog is not configured", Tasks: map[string]playbook.TaskStats{}, Outcomes: map[string]int64{}}
	if s.playbooks != nil {
		status, _ = s.playbooks.Status(r.Context())
	}
	tasks := map[string]any{}
	var input, output, total int64
	usageAvailable := false
	for _, name := range []string{"playbook.digest", "playbook.resolve", "playbook.learn"} {
		stats := status.Tasks[strings.TrimPrefix(name, "playbook.")]
		var usage any
		if stats.UsageAvailable {
			usageAvailable = true
			usage = map[string]int64{"input_tokens": stats.InputTokens, "output_tokens": stats.OutputTokens, "total_tokens": stats.TotalTokens}
			input += stats.InputTokens
			output += stats.OutputTokens
			total += stats.TotalTokens
		}
		tasks[name] = map[string]any{"calls": stats.Calls, "errors": stats.Errors, "token_usage": usage, "usage_reported_calls": stats.UsageReportedCalls, "usage_unavailable_calls": stats.UsageUnavailableCalls}
	}
	var usage any
	if usageAvailable {
		usage = map[string]int64{"input_tokens": input, "output_tokens": output, "total_tokens": total}
	}
	// Numeric token counters must bypass the generic secret-field redactor.
	// All free-form strings are sanitized before this bounded status projection.
	outcomes := map[string]int64{}
	for name, count := range status.Outcomes {
		outcomes[s.redactor.SanitizeText(name)] = count
	}
	response := map[string]any{"enabled": status.Enabled, "available": status.Available, "reason": s.redactor.SanitizeText(status.Reason), "catalog": status.Catalog, "tasks": tasks, "outcomes": outcomes, "token_usage": usage, "usage_note": "Token usage is unavailable until reported by the provider; monetary cost is unavailable.", "provider": s.redactor.SanitizeText(s.runtime.LLMProvider), "model": s.redactor.SanitizeText(s.runtime.LLMModel)}
	payload, err := json.Marshal(response)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "response serialization failed")
		return
	}
	if int64(len(payload)) > s.maxResponseBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, "response body too large")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}
