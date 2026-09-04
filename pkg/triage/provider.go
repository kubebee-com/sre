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
	Explain(ctx context.Context, query string, issue *scanner.Issue) (string, error)
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
  "action_type": "RestartPod" | "DeleteFailedPod" | "ScaleWorkload" | "RolloutRestart" | "CordonNode" | "GitOpsPR" | "Manual",
  "proposed_command": "kubectl or git command to run",
  "confidence_score": 0.95
}`

const ChatSystemPrompt = `You are Kubebee SRE AI, an expert Kubernetes Site Reliability Engineering assistant.
Help the user understand cluster incidents, pod crashes, logs, events, metrics, and remediation workflows.
Provide direct, concise, and technically accurate responses with copy-pasteable kubectl or GitOps commands where appropriate.`

func BuildPrompt(issue *scanner.Issue) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Resource: %s/%s (Namespace: %s)\n", issue.Kind, issue.Name, issue.Namespace))
	b.WriteString(fmt.Sprintf("Category: %s\n", issue.Category))
	b.WriteString(fmt.Sprintf("Initial Summary: %s\n", issue.Summary))
	b.WriteString(fmt.Sprintf("Details: %s\n", issue.Details))

	if issue.SpecSnippet != "" {
		b.WriteString(fmt.Sprintf("\nResource Spec Snippet:\n%s\n", issue.SpecSnippet))
	}

	if len(issue.Events) > 0 {
		b.WriteString("\nRecent Warning Events:\n")
		for _, e := range issue.Events {
			b.WriteString(fmt.Sprintf("- %s\n", e))
		}
	}

	if issue.LogsSnippet != "" {
		b.WriteString("\nSanitized Tail Logs (last 30 lines):\n")
		b.WriteString("```\n")
		b.WriteString(issue.LogsSnippet)
		b.WriteString("\n```\n")
	}

	b.WriteString("\nProvide diagnosis and remediation plan in strict JSON format.")
	return b.String()
}

func ParseDiagnosisJSON(raw string, issueID, providerName string) (*Diagnosis, error) {
	clean := strings.TrimSpace(raw)
	if strings.HasPrefix(clean, "```json") {
		clean = strings.TrimPrefix(clean, "```json")
		clean = strings.TrimSuffix(clean, "```")
		clean = strings.TrimSpace(clean)
	} else if strings.HasPrefix(clean, "```") {
		clean = strings.TrimPrefix(clean, "```")
		clean = strings.TrimSuffix(clean, "```")
		clean = strings.TrimSpace(clean)
	}

	var d Diagnosis
	if err := json.Unmarshal([]byte(clean), &d); err != nil {
		return nil, fmt.Errorf("failed to parse diagnosis JSON: %w (raw: %s)", err, raw)
	}

	d.IssueID = issueID
	d.ProviderName = providerName
	if d.ActionType == "" {
		d.ActionType = ActionManual
	}
	return &d, nil
}
