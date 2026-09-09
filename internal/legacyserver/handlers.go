package legacyserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kubebee-com/sre/pkg/buildinfo"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/triage"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const statusClientClosedRequest = 499

var serverQueryableResourceKinds = map[string]struct{}{
	"pod": {}, "service": {}, "configmap": {}, "persistentvolumeclaim": {},
	"deployment": {}, "statefulset": {}, "daemonset": {}, "replicaset": {},
	"job": {}, "cronjob": {}, "ingress": {}, "networkpolicy": {},
	"horizontalpodautoscaler": {}, "poddisruptionbudget": {}, "node": {},
}

func canonicalServerResourceKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if slash := strings.LastIndexByte(kind, '/'); slash >= 0 {
		kind = kind[slash+1:]
	}
	switch kind {
	case "pods":
		return "pod"
	case "services":
		return "service"
	case "configmaps":
		return "configmap"
	case "persistentvolumeclaims", "pvc", "pvcs":
		return "persistentvolumeclaim"
	case "deployments":
		return "deployment"
	case "statefulsets":
		return "statefulset"
	case "daemonsets":
		return "daemonset"
	case "replicasets":
		return "replicaset"
	case "jobs":
		return "job"
	case "cronjobs":
		return "cronjob"
	case "ingresses":
		return "ingress"
	case "networkpolicies", "netpol", "netpols":
		return "networkpolicy"
	case "hpa", "horizontalpodautoscalers":
		return "horizontalpodautoscaler"
	case "pdb", "poddisruptionbudgets":
		return "poddisruptionbudget"
	case "nodes":
		return "node"
	case "secret", "secrets", "secretlist":
		return "secret"
	default:
		return kind
	}
}

func validateServerQueryableKind(kind string) error {
	canonical := canonicalServerResourceKind(kind)
	if canonical == "secret" {
		return scanner.ErrSecretResource
	}
	if _, ok := serverQueryableResourceKinds[canonical]; !ok {
		return fmt.Errorf("resource kind %q is not queryable", strings.TrimSpace(kind))
	}
	return nil
}

type StatusResponse struct {
	LLMProvider             string            `json:"llm_provider"`
	LastScan                time.Time         `json:"last_scan"`
	ActiveIssuesCount       int               `json:"active_issues_count"`
	PendingProposalsCount   int               `json:"pending_proposals_count"`
	CompletedProposalsCount int               `json:"completed_proposals_count"`
	Version                 string            `json:"version"`
	ErrorCounts             map[string]uint64 `json:"error_counts"`
	TokenUsage              TokenUsageStatus  `json:"token_usage"`
	Settings                StatusSettings    `json:"settings"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	lastScan := s.lastScan
	s.mu.RUnlock()
	issuesCount := len(s.issueSnapshot())

	var proposals []*remediation.Proposal
	if s.engine != nil {
		var err error
		proposals, err = s.engine.ListProposalsWithError()
		if err != nil {
			s.writeError(w, http.StatusServiceUnavailable, "proposal storage unavailable")
			return
		}
	}
	pendingCount := 0
	completedCount := 0
	for _, p := range proposals {
		if p.Status == remediation.StatusPending {
			pendingCount++
		} else if p.Status == remediation.StatusCompleted {
			completedCount++
		}
	}

	providerName := ""
	if s.triage != nil {
		providerName = s.redactor.SanitizeText(s.triage.Name())
	}
	errorCounts := s.statusErrorSnapshot()
	resp := StatusResponse{
		LLMProvider:             providerName,
		LastScan:                lastScan,
		ActiveIssuesCount:       issuesCount,
		PendingProposalsCount:   pendingCount,
		CompletedProposalsCount: completedCount,
		Version:                 buildinfo.String(),
		ErrorCounts:             errorCounts,
		TokenUsage:              s.tokenUsageStatus(),
		Settings:                s.statusSettings(),
	}

	s.writeStatusJSON(w, http.StatusOK, resp)
}

func (s *Server) writeStatusJSON(w http.ResponseWriter, status int, response StatusResponse) {
	response.LLMProvider = s.redactor.SanitizeText(response.LLMProvider)
	response.Version = s.redactor.SanitizeText(response.Version)
	settings := response.Settings
	for index := range settings.AllowedOrigins {
		settings.AllowedOrigins[index] = s.redactor.SanitizeURL(settings.AllowedOrigins[index])
	}
	response.Settings = settings
	payload, err := json.Marshal(response)
	if err != nil {
		writeErrorWithRedactor(w, http.StatusInternalServerError, "response serialization failed", s.redactor)
		return
	}
	if s.maxResponseBytes > 0 && int64(len(payload)) > s.maxResponseBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, "response body too large")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, string(payload))
	_, _ = io.WriteString(w, "\n")
}

func (s *Server) statusErrorSnapshot() map[string]uint64 {
	if s == nil {
		return map[string]uint64{}
	}
	s.statusMetricsMu.Lock()
	defer s.statusMetricsMu.Unlock()
	counts := make(map[string]uint64, len(s.statusErrorCounts))
	for code, count := range s.statusErrorCounts {
		counts[code] = count
	}
	if s.metrics != nil {
		for source, count := range s.metrics.Snapshot().ErrorCounts {
			counts[source] += count
		}
	}
	if s.engine != nil {
		counts["remediation_persistence"] = s.engine.PersistenceErrors()
	}
	return counts
}

func (s *Server) tokenUsageStatus() TokenUsageStatus {
	if s.metrics != nil {
		snapshot := s.metrics.Snapshot()
		if snapshot.ProviderUsageSeen {
			return TokenUsageStatus{
				InputTokens:  snapshot.InputTokens,
				OutputTokens: snapshot.OutputTokens,
				TotalTokens:  snapshot.TotalTokens,
				Estimated:    false,
			}
		}
	}
	input := s.inputTokens.Load()
	output := s.outputTokens.Load()
	return TokenUsageStatus{InputTokens: input, OutputTokens: output, TotalTokens: input + output, Estimated: true}
}

func (s *Server) statusSettings() StatusSettings {
	origins := make([]string, 0, len(s.allowedOrigins))
	for origin := range s.allowedOrigins {
		if origin != "*" {
			origins = append(origins, origin)
		}
	}
	slices.Sort(origins)
	settings := StatusSettings{
		APITokenRequired:    s.authenticator != nil && s.authenticator.enabled,
		AllowedOrigins:      origins,
		MaxRequestBytes:     s.maxBodyBytes,
		MaxResponseBytes:    s.maxResponseBytes,
		RequestsPerMinute:   s.requestsPerMinute,
		RequestBurst:        s.requestBurst,
		ReadinessManaged:    s.readiness != nil,
		LLMProvider:         s.runtime.LLMProvider,
		LLMMode:             s.runtime.LLMMode,
		LLMWireAPI:          s.runtime.LLMWireAPI,
		LLMModel:            s.runtime.LLMModel,
		LLMBaseURLDisplay:   s.runtime.LLMBaseURLDisplay,
		ScanInterval:        s.runtime.ScanInterval,
		ScanJitter:          s.runtime.ScanJitter,
		EventDrivenScanning: s.runtime.EventDrivenScanning,
		EventQueueCapacity:  s.runtime.EventQueueCapacity,
		EventDebounce:       s.runtime.EventDebounce,
		CacheEnabled:        s.runtime.CacheEnabled,
		CacheConfigured:     s.runtime.CacheConfigured,
	}
	if s.notifier != nil {
		settings.WebhookConfigured = s.notifier.HasWebhookURL()
	}
	return settings
}

func (s *Server) handleListIssues(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ns := r.URL.Query().Get("namespace")
	severity := r.URL.Query().Get("severity")
	category := r.URL.Query().Get("category")

	var filtered []*scanner.SanitizedIssue
	for _, issue := range s.issueSnapshot() {
		if ns != "" && issue.Namespace != ns {
			continue
		}
		if severity != "" && string(issue.Severity) != severity {
			continue
		}
		if category != "" && string(issue.Category) != category {
			continue
		}
		filtered = append(filtered, scanner.SanitizeIssueWithRedactor(issue, s.redactor))
	}

	s.writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handleListProposals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	statusFilter := r.URL.Query().Get("status")
	if s.engine == nil {
		s.writeError(w, http.StatusServiceUnavailable, "remediation engine unavailable")
		return
	}
	all, err := s.engine.ListProposalsWithError()
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "proposal storage unavailable")
		return
	}

	if statusFilter == "" {
		s.writeJSON(w, http.StatusOK, s.sanitizeProposalResponses(all))
		return
	}

	var filtered []*remediation.SanitizedProposal
	for _, p := range all {
		if string(p.Status) == statusFilter {
			filtered = append(filtered, s.sanitizeProposalResponse(p))
		}
	}
	s.writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.engine == nil {
		s.writeError(w, http.StatusServiceUnavailable, "remediation engine unavailable")
		return
	}
	proposalID := strings.TrimSpace(r.URL.Query().Get("proposal_id"))
	events, err := s.engine.ListAuditEvents(proposalID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "audit history unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, events)
}

func (s *Server) handleProposalAction(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		s.writeError(w, http.StatusServiceUnavailable, "remediation engine unavailable")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// Expected: /api/proposals/{id}/{action}
	if len(parts) < 4 {
		http.NotFound(w, r)
		return
	}

	id := parts[2]
	action := parts[3]

	switch action {
	case "approve":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user := requestActor(s, r)
		if user == "" {
			s.writeError(w, http.StatusUnauthorized, "authenticated actor is required")
			return
		}
		proposal, err := s.engine.Approve(r.Context(), id, user)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, remediation.ErrActorRequired) {
				status = http.StatusUnauthorized
			} else if errors.Is(err, remediation.ErrStalePrecondition) || errors.Is(err, remediation.ErrMissingPrecondition) {
				status = http.StatusConflict
			}
			s.writeError(w, status, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, s.sanitizeProposalResponse(proposal))

	case "reject":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !requireJSONContentType(w, r) {
			return
		}
		var req struct {
			Reason string `json:"reason"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		user := requestActor(s, r)
		if user == "" {
			s.writeError(w, http.StatusUnauthorized, "authenticated actor is required")
			return
		}
		proposal, err := s.engine.Reject(id, user, req.Reason)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, s.sanitizeProposalResponse(proposal))

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.scanner == nil {
		s.writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	ns := r.URL.Query().Get("namespace")
	issues, err := s.scanner.Scan(r.Context(), ns)
	if err != nil {
		s.writeOperationError(w, r, http.StatusInternalServerError, "scan failed", err)
		return
	}

	s.UpdateScanResults(issues)
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":         "Scan triggered successfully",
		"anomalies_found": len(issues),
		"timestamp":       time.Now(),
	})
}

// handleAllowlistedQueryResource is the versioned query boundary. The
// compatibility handler remains available to older in-package callers, but
// public registration must validate the resource kind before any backend call.
func (s *Server) handleAllowlistedQueryResource(w http.ResponseWriter, r *http.Request) {
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
	if err := validateServerQueryableKind(request.Kind); err != nil {
		status := http.StatusBadRequest
		message := "invalid resource query"
		if errors.Is(err, scanner.ErrSecretResource) {
			status = http.StatusForbidden
			message = "resource cannot be queried"
		}
		s.writeError(w, status, message)
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
			status = statusClientClosedRequest
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

func (s *Server) handleValidatedVersionedScan(w http.ResponseWriter, r *http.Request) {
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
	for _, values := range [][]string{request.IncludeNamespaces, request.ExcludeNamespaces, request.Kinds, request.Names, request.Analyzers} {
		if len(values) > mcpMaxItems {
			s.writeError(w, http.StatusBadRequest, "scan request list exceeds limit")
			return
		}
		for _, value := range values {
			if err := validateMCPString("scan request", value); err != nil {
				s.writeError(w, http.StatusBadRequest, "scan request field exceeds limit")
				return
			}
		}
	}
	if err := validateMCPString("label selector", request.LabelSelector); err != nil {
		s.writeError(w, http.StatusBadRequest, "scan request field exceeds limit")
		return
	}
	plan, err := request.plan()
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid scan request")
		return
	}
	if plan.SchemaVersion == "" {
		plan.SchemaVersion = scanplan.SchemaVersion
	}
	known := make([]string, 0, mcpMaxItems)
	for _, info := range s.scanner.GetAnalyzers() {
		known = append(known, info.Name)
		if len(known) == mcpMaxItems {
			break
		}
	}
	if err := plan.Validate(known); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid scan request")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), scanplan.MaxScanTimeout)
	defer cancel()
	report, err := s.scanner.ScanWithPlan(ctx, plan)
	if err != nil {
		s.writeOperationError(w, r, http.StatusInternalServerError, "scan failed", err)
		return
	}
	if report == nil {
		s.writeError(w, http.StatusBadGateway, "scanner returned no report")
		return
	}
	s.UpdateScanResults(report.Issues)
	s.writeJSON(w, http.StatusOK, report)
}

// handleListAnalyzers returns all K8sGPT-compatible analyzers with active issue counts
func (s *Server) handleListAnalyzers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.scanner == nil {
		s.writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	analyzers := s.scanner.GetAnalyzers()

	issues := s.issueSnapshot()

	// Compute issue counts by resource kind
	for i := range analyzers {
		count := 0
		for _, issue := range issues {
			if issue == nil {
				continue
			}
			if strings.EqualFold(issue.Kind, analyzers[i].Resource) {
				count++
			}
		}
		analyzers[i].IssueCount = count
	}

	s.writeJSON(w, http.StatusOK, analyzerResponse(s.scanner, analyzers))
}

func analyzerResponse(source Scanner, analyzers []scanner.AnalyzerInfo) []interface{} {
	dynamicByName := make(map[string]scanner.DynamicAnalyzerInfo)
	if catalog, ok := source.(interface {
		DynamicAnalyzerInfos() []scanner.DynamicAnalyzerInfo
	}); ok {
		for _, info := range catalog.DynamicAnalyzerInfos() {
			dynamicByName[strings.ToLower(info.Name)] = info
		}
	}
	result := make([]interface{}, 0, len(analyzers))
	for _, info := range analyzers {
		if dynamic, ok := dynamicByName[strings.ToLower(info.Name)]; ok {
			dynamic.AnalyzerInfo = info
			result = append(result, dynamic)
			continue
		}
		result = append(result, info)
	}
	return result
}

// handleCleanPods lists current candidates and creates approval proposals for
// mutations. It never performs a direct delete from an HTTP request.
func (s *Server) handleCleanPods(w http.ResponseWriter, r *http.Request) {
	if s.scanner == nil {
		s.writeError(w, http.StatusServiceUnavailable, "scanner unavailable")
		return
	}
	cleaner := s.scanner.GetPodCleaner()
	if cleaner == nil {
		s.writeError(w, http.StatusInternalServerError, "Pod cleaner not initialized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		ns := r.URL.Query().Get("namespace")
		pods, err := cleaner.ListCleanablePods(r.Context(), ns)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, pods)

	case http.MethodPost:
		if !requireJSONContentType(w, r) {
			return
		}
		var req struct {
			Namespace string   `json:"namespace"`
			PodNames  []string `json:"pod_names"`
			DryRun    bool     `json:"dry_run"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}

		if len(req.PodNames) == 0 {
			s.writeError(w, http.StatusBadRequest, "pod_names list cannot be empty")
			return
		}

		if req.DryRun {
			report, err := cleaner.CleanPods(r.Context(), req.Namespace, req.PodNames, true)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.writeJSON(w, http.StatusOK, report)
			return
		}

		actor := requestActor(s, r)
		if actor == "" {
			s.writeError(w, http.StatusUnauthorized, "authenticated actor is required")
			return
		}
		candidates, err := cleaner.ListCleanablePods(r.Context(), req.Namespace)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		byName := make(map[string]*scanner.CleanablePod, len(candidates))
		for _, candidate := range candidates {
			if _, exists := byName[candidate.Name]; exists {
				// An all-namespace request must identify a unique target. Requiring
				// namespace in that case avoids approving the wrong pod.
				byName[candidate.Name] = nil
				continue
			}
			byName[candidate.Name] = candidate
		}

		selected := make([]*scanner.CleanablePod, 0, len(req.PodNames))
		seen := make(map[string]struct{}, len(req.PodNames))
		for _, name := range req.PodNames {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if _, duplicate := seen[name]; duplicate {
				continue
			}
			seen[name] = struct{}{}
			candidate, ok := byName[name]
			if !ok || candidate == nil {
				s.writeError(w, http.StatusConflict, "one or more requested pods are not currently eligible for cleanup")
				return
			}
			selected = append(selected, candidate)
		}
		if len(selected) == 0 {
			s.writeError(w, http.StatusBadRequest, "pod_names list cannot be empty")
			return
		}

		proposals := make([]*remediation.Proposal, 0, len(selected))
		for _, candidate := range selected {
			issue := &scanner.Issue{
				ID:                    fmt.Sprintf("cleanup-%s-%s-%s", candidate.Namespace, candidate.Name, candidate.TargetUID),
				Namespace:             candidate.Namespace,
				Kind:                  "Pod",
				Name:                  candidate.Name,
				TargetUID:             candidate.TargetUID,
				TargetResourceVersion: candidate.TargetResourceVersion,
				Severity:              scanner.SeverityMedium,
				Category:              scanner.CategoryPodFailed,
				Summary:               fmt.Sprintf("Pod %s is eligible for authorized cleanup", candidate.Name),
				Details:               fmt.Sprintf("Current cleanup reason: %s", candidate.Reason),
				FirstObserved:         time.Now().UTC(),
				LastObserved:          time.Now().UTC(),
			}
			diagnosis := &triage.Diagnosis{
				IssueID:         issue.ID,
				Summary:         issue.Summary,
				RootCause:       issue.Details,
				Severity:        issue.Severity,
				RemediationPlan: "Delete the currently eligible pod only after human approval and target precondition checks.",
				ActionType:      triage.ActionCleanupPods,
				ProposedCommand: fmt.Sprintf("kubectl delete pod %s -n %s", candidate.Name, candidate.Namespace),
				ConfidenceScore: 1,
				ProviderName:    "cleanup-policy",
			}
			if s.engine == nil {
				s.writeError(w, http.StatusServiceUnavailable, "remediation engine unavailable")
				return
			}
			proposal, err := s.engine.CreateProposalForActor(issue, diagnosis, actor)
			if err != nil {
				s.writeError(w, http.StatusConflict, "cleanup proposal could not be created")
				return
			}
			proposals = append(proposals, proposal)
		}
		candidateNames := make([]string, 0, len(selected))
		for _, candidate := range selected {
			candidateNames = append(candidateNames, candidate.Name)
		}
		s.writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"candidate_pods": candidateNames,
			"proposals":      s.sanitizeProposalResponses(proposals),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleChat handles conversational interaction with SRE AI
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}

	var req struct {
		Message   string `json:"message"`
		IssueID   string `json:"issue_id,omitempty"`
		SessionID string `json:"session_id,omitempty"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}

	if strings.TrimSpace(req.Message) == "" {
		s.writeError(w, http.StatusBadRequest, "message cannot be empty")
		return
	}
	if sessionID := strings.TrimSpace(req.SessionID); sessionID != "" {
		if s.chatSessions == nil {
			s.writeError(w, http.StatusServiceUnavailable, "chat sessions are unavailable")
			return
		}
		reply, err := s.chatSessions.Send(r.Context(), requestActor(s, r), sessionID, req.Message)
		if err != nil {
			s.writeChatError(w, err)
			return
		}
		s.recordTokenUsage(req.Message, reply)
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"schema_version": chatSchemaVersion,
			"session_id":     sessionID,
			"reply":          reply,
		})
		return
	}

	var matchingIssue *scanner.Issue
	if req.IssueID != "" {
		for _, issue := range s.issueSnapshot() {
			if issue.ID == req.IssueID {
				matchingIssue = issue
				break
			}
		}
	}

	if matchingIssue != nil {
		matchingIssue = scanner.SanitizeIssueWithRedactor(matchingIssue, s.redactor).AsIssue()
	}
	if s.triage == nil {
		s.writeError(w, http.StatusServiceUnavailable, "AI response unavailable")
		return
	}
	reply, err := s.triage.Explain(r.Context(), s.redactor.SanitizeText(req.Message), matchingIssue)
	if err != nil {
		s.writeOperationError(w, r, http.StatusInternalServerError, "AI response unavailable", err)
		return
	}
	s.recordTokenUsage(req.Message, reply)

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"reply":     reply,
		"provider":  s.triage.Name(),
		"timestamp": time.Now(),
	})
}

// handleTestNotification dispatches a test alert via the configured or provided webhook
func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONContentType(w, r) {
		return
	}

	var req struct {
		WebhookURL string `json:"webhook_url,omitempty"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}

	if s.notifier == nil {
		s.writeError(w, http.StatusInternalServerError, "notifier service not available")
		return
	}

	err := s.notifier.SendTestNotification(r.Context(), req.WebhookURL)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("notification delivery failed: %v", err))
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Test notification delivered successfully",
	})
}

// handleConfig returns and updates runtime configurations
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings := s.statusSettings()
		providerName := ""
		if s.triage != nil {
			providerName = s.redactor.SanitizeText(s.triage.Name())
		}
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"llm_provider":         providerName,
			"settings":             settings,
			"llm_mode":             settings.LLMMode,
			"llm_wire_api":         settings.LLMWireAPI,
			"llm_model":            settings.LLMModel,
			"llm_base_url_display": settings.LLMBaseURLDisplay,
			"scan_interval":        settings.ScanInterval,
			"scan_jitter":          settings.ScanJitter,
			"cache_enabled":        settings.CacheEnabled,
			"webhook_configured":   settings.WebhookConfigured,
		})

	case http.MethodPost:
		if !requireJSONContentType(w, r) {
			return
		}
		var req struct {
			WebhookURL *string `json:"webhook_url"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		if s.notifier != nil && req.WebhookURL != nil {
			if err := s.notifier.SetWebhookURL(*req.WebhookURL); err != nil {
				s.writeError(w, http.StatusBadRequest, "webhook URL is not allowed")
				return
			}
		}
		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "success",
			"message": "Configuration updated",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	if s.maxResponseBytes > 0 {
		if payload, err := json.Marshal(data); err == nil && int64(len(payload)) > s.maxResponseBytes {
			s.writeError(w, http.StatusRequestEntityTooLarge, "response body too large")
			return
		}
	}
	writeJSONWithRedactor(w, status, data, s.redactor)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.recordBoundaryError(status)
	writeErrorWithRedactor(w, status, message, s.redactor)
}

func (s *Server) recordBoundaryError(status int) {
	if s == nil {
		return
	}
	code := boundaryErrorCode(status)
	s.statusMetricsMu.Lock()
	if s.statusErrorCounts == nil {
		s.statusErrorCounts = make(map[string]uint64)
	}
	s.statusErrorCounts[code]++
	s.statusMetricsMu.Unlock()
}

func (s *Server) recordTokenUsage(input, output string) {
	if s == nil {
		return
	}
	s.inputTokens.Add(estimatedTokenCount(input))
	s.outputTokens.Add(estimatedTokenCount(output))
}

func estimatedTokenCount(value string) uint64 {
	count := utf8.RuneCountInString(value)
	if count <= 0 {
		return 0
	}
	const maximum = 1 << 20
	if count > maximum*4 {
		return maximum
	}
	return uint64((count + 3) / 4)
}

func (s *Server) writeOperationError(w http.ResponseWriter, r *http.Request, fallbackStatus int, message string, err error) {
	status := fallbackStatus
	safeMessage := message
	if errors.Is(err, context.Canceled) || (r != nil && errors.Is(r.Context().Err(), context.Canceled)) {
		status = statusClientClosedRequest
		safeMessage = "request canceled"
	} else if errors.Is(err, context.DeadlineExceeded) || (r != nil && errors.Is(r.Context().Err(), context.DeadlineExceeded)) {
		status = http.StatusGatewayTimeout
		safeMessage = "request timed out"
	}
	s.writeError(w, status, safeMessage)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	writeJSONWithRedactor(w, status, data, nil)
}

func writeJSONWithRedactor(w http.ResponseWriter, status int, data interface{}, redactor *sanitizer.Redactor) {
	payload, err := json.Marshal(data)
	if err != nil {
		payload = []byte(`{"error":"response serialization failed"}`)
	} else {
		if redactor == nil {
			redactor = sanitizer.NewRedactor()
		}
		payload = []byte(redactor.SanitizeJSON(string(payload)))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, string(payload))
	_, _ = io.WriteString(w, "\n")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeErrorWithRedactor(w, status, message, nil)
}

func writeErrorWithRedactor(w http.ResponseWriter, status int, message string, redactor *sanitizer.Redactor) {
	writeJSONWithRedactor(w, status, map[string]interface{}{
		"schema_version": "error/v1",
		"code":           boundaryErrorCode(status),
		"status":         status,
		"error":          message,
	}, redactor)
}

func boundaryErrorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case statusClientClosedRequest:
		return "request_canceled"
	case http.StatusGatewayTimeout:
		return "deadline_exceeded"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusUnsupportedMediaType:
		return "unsupported_media_type"
	case http.StatusServiceUnavailable:
		return "service_unavailable"
	default:
		if status >= 500 {
			return "internal_error"
		}
		return "request_failed"
	}
}

func (s *Server) sanitizeProposalResponses(proposals []*remediation.Proposal) []*remediation.SanitizedProposal {
	responses := make([]*remediation.SanitizedProposal, 0, len(proposals))
	for _, proposal := range proposals {
		responses = append(responses, s.sanitizeProposalResponse(proposal))
	}
	return responses
}

func (s *Server) sanitizeProposalResponse(proposal *remediation.Proposal) *remediation.SanitizedProposal {
	return proposal.SanitizedWithRedactor(s.redactor)
}

func requestActor(s *Server, r *http.Request) string {
	actor := actorFromContext(r.Context())
	if actor == "" && !s.authenticator.enabled {
		return localActor
	}
	return actor
}

func requireJSONContentType(w http.ResponseWriter, r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || (mediaType != "application/json" && !strings.HasSuffix(strings.ToLower(mediaType), "+json")) {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination interface{}) bool {
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(destination); err != nil {
		writeDecodeError(w, err)
		return false
	}

	var extra interface{}
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

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid request payload")
}
