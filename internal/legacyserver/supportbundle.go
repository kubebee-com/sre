package legacyserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/supportbundle"
)

type supportBundleRequest struct {
	IncludeResources bool                        `json:"include_resources,omitempty"`
	Resources        []supportBundleResourceSpec `json:"resources,omitempty"`
}

type supportBundleResourceSpec struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// handleSupportBundle creates a bounded, sanitized archive from the latest
// in-memory findings and optional explicitly named resources. It returns the
// archive directly so the server never accepts an arbitrary filesystem path.
func (s *Server) handleSupportBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}
	if s.scanner == nil {
		s.writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	var request supportBundleRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &request) {
		return
	}
	if len(request.Resources) > 0 && !request.IncludeResources {
		s.writeError(w, http.StatusBadRequest, "resource exports require include_resources=true")
		return
	}
	if len(request.Resources) > mcpMaxItems {
		s.writeError(w, http.StatusRequestEntityTooLarge, "support bundle resource list exceeds limit")
		return
	}

	issues := s.issueSnapshot()

	analyzerRuns := make([]scanner.AnalyzerRun, 0)
	for _, info := range s.scanner.GetAnalyzers() {
		analyzerRuns = append(analyzerRuns, scanner.AnalyzerRun{Info: info})
	}
	var history []scanner.HistoryEntry
	if store := s.scanner.History(); store != nil {
		var err error
		history, err = store.List()
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "scan history unavailable")
			return
		}
	}

	resources := make([]supportbundle.ResourcePayload, 0, len(request.Resources))
	queryContext, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	for _, selected := range request.Resources {
		kind := strings.TrimSpace(selected.Kind)
		namespace := strings.TrimSpace(selected.Namespace)
		name := strings.TrimSpace(selected.Name)
		if kind == "" || name == "" || len(kind) > mcpMaxStringBytes || len(namespace) > mcpMaxStringBytes || len(name) > mcpMaxStringBytes || strings.ContainsAny(kind+namespace+name, "\r\n\x00") {
			s.writeError(w, http.StatusBadRequest, "resource identifiers are invalid")
			return
		}
		if err := validateServerQueryableKind(kind); err != nil {
			s.writeError(w, http.StatusBadRequest, "resource cannot be exported")
			return
		}
		resource, err := s.scanner.QueryResource(queryContext, kind, namespace, name)
		if err != nil {
			s.writeOperationError(w, r, http.StatusBadRequest, "resource could not be queried", err)
			return
		}
		safeResource, err := scanner.SanitizeResourceForKind(kind, resource, s.redactor)
		if err != nil {
			if errors.Is(err, scanner.ErrSecretResource) {
				s.writeError(w, http.StatusBadRequest, "Secret resources cannot be exported")
			} else {
				s.writeError(w, http.StatusInternalServerError, "resource projection failed")
			}
			return
		}
		encoded, err := json.Marshal(safeResource)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "resource projection failed")
			return
		}
		resources = append(resources, supportbundle.ResourcePayload{Kind: kind, Namespace: namespace, Name: name, Data: encoded})
	}

	archive, err := supportbundle.Build(supportbundle.Input{
		Issues:       issues,
		Analyzers:    analyzerRuns,
		History:      history,
		Resources:    resources,
		SecretValues: s.redactionSecretValues(),
	}, supportbundle.Options{IncludeResources: request.IncludeResources})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "support bundle could not be created")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="sre-support-bundle.zip"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(archive)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(archive)
}

func (s *Server) redactionSecretValues() []string {
	return append([]string(nil), s.redactionSecrets...)
}
