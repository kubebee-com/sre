package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kubebee-com/sre/pkg/scanner"
)

type TriageProvider interface {
	Name() string
	Diagnose(ctx context.Context, issue *scanner.Issue) (*Diagnosis, error)
}

const SystemPrompt = `You are a Principal Kubernetes Site Reliability Engineer (SRE).
Your task is to analyze Kubernetes anomalies, logs, and events, determine the precise root cause, and propose safe remediation.

RULES:
1. Be succinct, factual, and actionable.
2. For transient failures (e.g. deadlocks, temporary network timeout, zombie processes), prefer ActionType "RestartPod" or "DeleteFailedPod".
3. For resource exhaustion (e.g. OOMKilled exit code 137), identify the memory spike and prefer ActionType "GitOpsPR" or "ScaleWorkload" or "RestartPod".
4. For persistent code or configuration bugs, prefer ActionType "GitOpsPR" or "Manual".
5. Return strictly valid JSON conforming to the following structure:
{
  "summary": "Short 1-line summary of what happened",
  "root_cause": "Detailed technical root cause based on logs and events",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "remediation_plan": "Step-by-step description of how to fix this issue",
  "action_type": "RestartPod" | "DeleteFailedPod" | "ScaleWorkload" | "CordonNode" | "GitOpsPR" | "Manual",
  "proposed_command": "kubectl or git command to run",
  "confidence_score": 0.95
}`

func BuildPrompt(issue *scanner.Issue) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Resource: %s/%s (Namespace: %s)\n", issue.Kind, issue.Name, issue.Namespace))
	b.WriteString(fmt.Sprintf("Category: %s\n", issue.Category))
	b.WriteString(fmt.Sprintf("Initial Summary: %s\n", issue.Summary))
	b.WriteString(fmt.Sprintf("Details: %s\n", issue.Details))

	if len(issue.Events) > 0 {
		b.WriteString("\nRecent Warning Events:\n")
		for _, e := range issue.Events {
			b.WriteString(fmt.Sprintf("- %s\n", e))
		}
	}

	if issue.LogsSnippet != "" {
		b.WriteString("\nRecent Container Logs (last lines):\n")
		b.WriteString("```\n")
		b.WriteString(issue.LogsSnippet)
		b.WriteString("\n```\n")
	}

	b.WriteString("\nPlease analyze the above data and provide the JSON diagnosis and proposed remediation.")
	return b.String()
}

func parseJSONResponse(issueID, raw, providerName string) (*Diagnosis, error) {
	// Clean markdown fences if present
	clean := strings.TrimSpace(raw)
	if strings.HasPrefix(clean, "```json") {
		clean = strings.TrimPrefix(clean, "```json")
		clean = strings.TrimSuffix(clean, "```")
	} else if strings.HasPrefix(clean, "```") {
		clean = strings.TrimPrefix(clean, "```")
		clean = strings.TrimSuffix(clean, "```")
	}
	clean = strings.TrimSpace(clean)

	var diag Diagnosis
	if err := json.Unmarshal([]byte(clean), &diag); err != nil {
		return nil, fmt.Errorf("unmarshal LLM JSON response: %w (raw: %s)", err, raw)
	}

	diag.IssueID = issueID
	diag.ProviderName = providerName
	if diag.ConfidenceScore == 0 {
		diag.ConfidenceScore = 0.85
	}
	return &diag, nil
}
