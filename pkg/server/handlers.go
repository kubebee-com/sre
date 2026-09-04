package server

import (
	"context"
	"encoding/json"
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
	issues := s.activeIssues
	s.mu.RUnlock()

	if issues == nil {
		issues = []*scanner.Issue{}
	}
	writeJSON(w, http.StatusOK, issues)
}

func (s *Server) handleListProposals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	proposals := s.engine.ListProposals()
	writeJSON(w, http.StatusOK, proposals)
}

type actionRequest struct {
	ApprovedBy string `json:"approved_by"`
	RejectedBy string `json:"rejected_by"`
}

func (s *Server) handleProposalAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// URL format: /api/proposals/{id}/approve or /api/proposals/{id}/reject
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 {
		http.Error(w, "Invalid proposal action path", http.StatusBadRequest)
		return
	}

	proposalID := parts[2]
	action := parts[3]

	var req actionRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	switch action {
	case "approve":
		approver := req.ApprovedBy
		if approver == "" {
			approver = "Web Operator"
		}
		p, err := s.engine.Approve(context.Background(), proposalID, approver)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, p)

	case "reject":
		rejecter := req.RejectedBy
		if rejecter == "" {
			rejecter = "Web Operator"
		}
		p, err := s.engine.Reject(proposalID, rejecter)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, p)

	default:
		http.Error(w, "Unknown action: "+action, http.StatusBadRequest)
	}
}

func (s *Server) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		issues, err := s.scanner.Scan(ctx, "")
		if err != nil {
			return
		}
		s.SetActiveIssues(issues)

		// Triage each issue and generate proposals
		for _, issue := range issues {
			diag, err := s.triage.Diagnose(ctx, issue)
			if err == nil && diag != nil {
				s.engine.CreateProposal(issue, diag)
			}
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "Scan triggered"})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
