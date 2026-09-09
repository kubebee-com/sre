package legacyserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const compatibilitySchemaVersion = "api/v1"

type scanRequest struct {
	SchemaVersion     string   `json:"schema_version,omitempty"`
	IncludeNamespaces []string `json:"include_namespaces,omitempty"`
	ExcludeNamespaces []string `json:"exclude_namespaces,omitempty"`
	LabelSelector     string   `json:"label_selector,omitempty"`
	Kinds             []string `json:"kinds,omitempty"`
	Names             []string `json:"names,omitempty"`
	Analyzers         []string `json:"analyzers,omitempty"`
	MaxConcurrency    int      `json:"max_concurrency,omitempty"`
	Timeout           string   `json:"timeout,omitempty"`
}

func (r scanRequest) plan() (scanplan.Plan, error) {
	plan := scanplan.Default()
	plan.SchemaVersion = r.SchemaVersion
	plan.IncludeNamespaces = append([]string(nil), r.IncludeNamespaces...)
	plan.ExcludeNamespaces = append([]string(nil), r.ExcludeNamespaces...)
	plan.LabelSelector = r.LabelSelector
	plan.Kinds = append([]string(nil), r.Kinds...)
	plan.Names = append([]string(nil), r.Names...)
	plan.Analyzers = append([]string(nil), r.Analyzers...)
	if r.MaxConcurrency != 0 {
		plan.MaxConcurrency = r.MaxConcurrency
	}
	if strings.TrimSpace(r.Timeout) != "" {
		duration, err := time.ParseDuration(r.Timeout)
		if err != nil {
			return scanplan.Plan{}, errors.New("timeout must be a valid duration")
		}
		plan.Timeout = duration
	}
	return plan, nil
}

type queryRequest struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (s *Server) handleVersionedScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var request scanRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &request) {
		return
	}
	if s.scanner == nil {
		s.writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	plan, err := request.plan()
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if plan.SchemaVersion == "" {
		plan.SchemaVersion = scanplan.SchemaVersion
	}
	ctx, cancel := context.WithTimeout(r.Context(), scanplan.MaxScanTimeout)
	defer cancel()
	report, err := s.scanner.ScanWithPlan(ctx, plan)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "unknown analyzer") || strings.Contains(err.Error(), "unsupported scan plan") {
			status = http.StatusBadRequest
		}
		s.writeError(w, status, err.Error())
		return
	}
	if report == nil {
		s.writeError(w, http.StatusBadGateway, "scanner returned no report")
		return
	}
	s.UpdateScanResults(report.Issues)
	s.writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleScanHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.scanner == nil || s.scanner.History() == nil {
		s.writeJSON(w, http.StatusOK, map[string]interface{}{"schema_version": "scan-history/v1", "entries": []scanner.HistoryEntry{}})
		return
	}
	entries, err := listHistory(s.scanner.History(), maxHistoryItems)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "scan history unavailable")
		return
	}
	if len(entries) > maxHistoryItems {
		s.writeError(w, http.StatusRequestEntityTooLarge, "history response exceeds item limit")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{"schema_version": "scan-history/v1", "entries": entries})
}

// BoundedHistoryStore is an optional server-facing capability. Existing
// scanner.HistoryStore implementations can continue to provide List only.
type BoundedHistoryStore interface {
	ListLimit(int) ([]scanner.HistoryEntry, error)
}

func listHistory(store scanner.HistoryStore, limit int) ([]scanner.HistoryEntry, error) {
	if bounded, ok := store.(BoundedHistoryStore); ok {
		return bounded.ListLimit(limit)
	}
	return store.List()
}

func (s *Server) handleQueryResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	var request queryRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if s.scanner == nil {
		s.writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resource, err := s.scanner.QueryResource(ctx, request.Kind, request.Namespace, request.Name)
	if err != nil {
		status := http.StatusInternalServerError
		message := "resource query failed"
		switch {
		case errors.Is(err, scanner.ErrSecretResource), apierrors.IsForbidden(err):
			status = http.StatusForbidden
			message = "resource cannot be queried"
		case apierrors.IsUnauthorized(err):
			status = http.StatusUnauthorized
			message = "resource query is unauthorized"
		case apierrors.IsNotFound(err):
			status = http.StatusNotFound
			message = "resource was not found"
		case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
			status = http.StatusGatewayTimeout
			message = "resource query timed out"
		case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
			status = http.StatusRequestTimeout
			message = "resource query canceled"
		case queryInputError(err):
			status = http.StatusBadRequest
			message = "invalid resource query"
		}
		s.writeError(w, status, message)
		return
	}
	safeResource, err := scanner.SanitizeResourceForKind(request.Kind, resource, s.redactor)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "resource projection failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"schema_version": compatibilitySchemaVersion,
		"kind":           request.Kind,
		"name":           request.Name,
		"namespace":      request.Namespace,
		"resource":       safeResource,
	})
}

func queryInputError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{"kind and name are required", "resource identifiers are invalid", "resource name is invalid", "namespace is invalid", "nodes are cluster-scoped", "resource kind"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	response := map[string]interface{}{
		"schema_version": "capabilities/v1",
		"dynamic":        []scanner.DynamicCapability{},
	}
	if capable, ok := s.scanner.(interface {
		DynamicCapabilities(context.Context) []scanner.DynamicCapability
	}); ok {
		response["dynamic"] = capable.DynamicCapabilities(r.Context())
	}
	s.writeJSON(w, http.StatusOK, response)
}
