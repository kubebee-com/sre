package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
)

type StatusResponse struct {
	LLMProvider             string    `json:"llm_provider"`
	LastScan                time.Time `json:"last_scan"`
	ActiveIssuesCount       int       `json:"active_issues_count"`
	PendingProposalsCount   int       `json:"pending_proposals_count"`
	CompletedProposalsCount int       `json:"completed_proposals_count"`
	Version                 string    `json:"version"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	lastScan := s.lastScan
	issuesCount := len(s.activeIssues)
	s.mu.RUnlock()

	proposals := s.engine.ListProposals()
	pendingCount := 0
	completedCount := 0
	for _, p := range proposals {
		if p.Status == remediation.StatusPending {
			pendingCount++
		} else if p.Status == remediation.StatusCompleted {
			completedCount++
		}
	}

	resp := StatusResponse{
		LLMProvider:             s.triage.Name(),
		LastScan:                lastScan,
		ActiveIssuesCount:       issuesCount,
		PendingProposalsCount:   pendingCount,
		CompletedProposalsCount: completedCount,
		Version:                 "1.0.0",
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListIssues(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	ns := r.URL.Query().Get("namespace")
	severity := r.URL.Query().Get("severity")
	category := r.URL.Query().Get("category")

	var filtered []*scanner.Issue
	for _, issue := range s.activeIssues {
		if ns != "" && issue.Namespace != ns {
			continue
		}
		if severity != "" && string(issue.Severity) != severity {
			continue
		}
		if category != "" && string(issue.Category) != category {
			continue
		}
		filtered = append(filtered, issue)
	}

	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handleListProposals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	statusFilter := r.URL.Query().Get("status")
	all := s.engine.ListProposals()

	if statusFilter == "" {
		writeJSON(w, http.StatusOK, all)
		return
	}

	var filtered []*remediation.Proposal
	for _, p := range all {
		if string(p.Status) == statusFilter {
			filtered = append(filtered, p)
		}
	}
	writeJSON(w, http.StatusOK, filtered)
}

func (s *Server) handleProposalAction(w http.ResponseWriter, r *http.Request) {
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
		user := r.Header.Get("X-User-Email")
		if user == "" {
			user = "sre-dashboard-user"
		}
		proposal, err := s.engine.Approve(context.Background(), id, user)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, proposal)

	case "reject":
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		user := r.Header.Get("X-User-Email")
		if user == "" {
			user = "sre-dashboard-user"
		}
		proposal, err := s.engine.Reject(id, user)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, proposal)

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ns := r.URL.Query().Get("namespace")
	issues, err := s.scanner.Scan(r.Context(), ns)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.UpdateScanResults(issues)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":        "Scan triggered successfully",
		"anomalies_found": len(issues),
		"timestamp":      time.Now(),
	})
}

// handleListAnalyzers returns all K8sGPT-compatible analyzers with active issue counts
func (s *Server) handleListAnalyzers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	analyzers := s.scanner.GetAnalyzers()

	s.mu.RLock()
	issues := s.activeIssues
	s.mu.RUnlock()

	// Compute issue counts by resource kind
	for i := range analyzers {
		count := 0
		for _, issue := range issues {
			if strings.EqualFold(issue.Kind, analyzers[i].Resource) {
				count++
			}
		}
		analyzers[i].IssueCount = count
	}

	writeJSON(w, http.StatusOK, analyzers)
}

// handleCleanPods handles listing cleanable pods (GET) and batch deleting them (POST)
func (s *Server) handleCleanPods(w http.ResponseWriter, r *http.Request) {
	cleaner := s.scanner.GetPodCleaner()
	if cleaner == nil {
		writeError(w, http.StatusInternalServerError, "Pod cleaner not initialized")
		return
	}

	switch r.Method {
	case http.MethodGet:
		ns := r.URL.Query().Get("namespace")
		pods, err := cleaner.ListCleanablePods(r.Context(), ns)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pods)

	case http.MethodPost:
		var req struct {
			Namespace string   `json:"namespace"`
			PodNames  []string `json:"pod_names"`
			DryRun    bool     `json:"dry_run"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request payload")
			return
		}

		if len(req.PodNames) == 0 {
			writeError(w, http.StatusBadRequest, "pod_names list cannot be empty")
			return
		}

		report, err := cleaner.CleanPods(r.Context(), req.Namespace, req.PodNames, req.DryRun)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, report)

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

	var req struct {
		Message string `json:"message"`
		IssueID string `json:"issue_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	if strings.TrimSpace(req.Message) == "" {
		writeError(w, http.StatusBadRequest, "message cannot be empty")
		return
	}

	var matchingIssue *scanner.Issue
	if req.IssueID != "" {
		s.mu.RLock()
		for _, issue := range s.activeIssues {
			if issue.ID == req.IssueID {
				matchingIssue = issue
				break
			}
		}
		s.mu.RUnlock()
	}

	reply, err := s.triage.Explain(r.Context(), req.Message, matchingIssue)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("AI response error: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
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

	var req struct {
		WebhookURL string `json:"webhook_url,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if s.notifier == nil {
		writeError(w, http.StatusInternalServerError, "notifier service not available")
		return
	}

	err := s.notifier.SendTestNotification(r.Context(), req.WebhookURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("notification delivery failed: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Test notification delivered successfully",
	})
}

// handleConfig returns and updates runtime configurations
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		webhookURL := ""
		if s.notifier != nil {
			webhookURL = s.notifier.GetWebhookURL()
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"llm_provider": s.triage.Name(),
			"webhook_url":  webhookURL,
		})

	case http.MethodPost:
		var req struct {
			WebhookURL string `json:"webhook_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid payload")
			return
		}
		if s.notifier != nil && req.WebhookURL != "" {
			s.notifier.SetWebhookURL(req.WebhookURL)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "success",
			"message": "Configuration updated",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
