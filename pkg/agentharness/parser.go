package agentharness

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/triage"
)

type rawSolutionPayload struct {
	Summary          string   `json:"summary"`
	RootCause        string   `json:"root_cause"`
	RemediationPlan  string   `json:"remediation_plan"`
	ActionType       string   `json:"action_type"`
	ProposedCommands []string `json:"proposed_commands"`
	ProposedCommand  string   `json:"proposed_command"`
	GitOpsPatch      string   `json:"gitops_patch"`
	VerificationPlan string   `json:"verification_plan"`
	RollbackPlan     string   `json:"rollback_plan"`
	ConfidenceScore  float64  `json:"confidence_score"`
}

// ParseSolutionOutput extracts and sanitizes a structured Solution from raw
// `codex exec` or `agy --print --output-format json` stdout.
func ParseSolutionOutput(raw string, harness HarnessKind, sandboxRuntime string, secretValues ...string) (*Solution, error) {
	redactor := sanitizer.RedactorForSecrets(secretValues...)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("agent harness returned empty output")
	}

	// Unwrap envelope formats like `agy --output-format json` (`{"result": "..."}`).
	trimmed = unwrapHarnessEnvelope(trimmed)

	jsonBlock := extractJSONObject(trimmed)
	if jsonBlock == "" {
		return nil, errors.New("agent harness output did not contain a valid JSON solution object")
	}

	var payload rawSolutionPayload
	if err := json.Unmarshal([]byte(jsonBlock), &payload); err != nil {
		return nil, fmt.Errorf("parse agent solution JSON: %w", err)
	}

	summary := strings.TrimSpace(redactor.SanitizeText(payload.Summary))
	rootCause := strings.TrimSpace(redactor.SanitizeText(payload.RootCause))
	plan := strings.TrimSpace(redactor.SanitizeText(payload.RemediationPlan))
	if summary == "" || plan == "" {
		return nil, errors.New("agent solution requires non-empty summary and remediation_plan")
	}

	commands := make([]string, 0, len(payload.ProposedCommands)+1)
	for _, cmd := range payload.ProposedCommands {
		if cleaned := strings.TrimSpace(redactor.SanitizeText(cmd)); cleaned != "" {
			commands = append(commands, cleaned)
		}
	}
	if len(commands) == 0 && strings.TrimSpace(payload.ProposedCommand) != "" {
		commands = append(commands, strings.TrimSpace(redactor.SanitizeText(payload.ProposedCommand)))
	}

	actionType := normalizeAgentActionType(payload.ActionType)
	confidence := payload.ConfidenceScore
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	return &Solution{
		Harness:          harness,
		SandboxRuntime:   sandboxRuntime,
		Summary:          summary,
		RootCause:        rootCause,
		RemediationPlan:  plan,
		ActionType:       actionType,
		ProposedCommands: commands,
		GitOpsPatch:      strings.TrimSpace(redactor.SanitizeText(payload.GitOpsPatch)),
		VerificationPlan: strings.TrimSpace(redactor.SanitizeText(payload.VerificationPlan)),
		RollbackPlan:     strings.TrimSpace(redactor.SanitizeText(payload.RollbackPlan)),
		ConfidenceScore:  confidence,
		RawOutput:        redactor.SanitizeText(raw),
	}, nil
}

func normalizeAgentActionType(raw string) triage.ActionType {
	switch triage.ActionType(strings.TrimSpace(raw)) {
	case triage.ActionAgentRemediation,
		triage.ActionGitOpsPR,
		triage.ActionRestartPod,
		triage.ActionDeleteFailedPod,
		triage.ActionRolloutRestart,
		triage.ActionScaleWorkload,
		triage.ActionCordonNode,
		triage.ActionCleanupPods,
		triage.ActionBumpVersion,
		triage.ActionUpgradeApp,
		triage.ActionManual:
		return triage.ActionType(strings.TrimSpace(raw))
	default:
		return triage.ActionAgentRemediation
	}
}

func unwrapHarnessEnvelope(raw string) string {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return raw
	}
	if _, hasSummary := envelope["summary"]; hasSummary {
		return raw
	}
	for _, key := range []string{"structured_output", "result", "output", "response", "text"} {
		field, ok := envelope[key]
		if !ok || len(field) == 0 {
			continue
		}
		var asString string
		if err := json.Unmarshal(field, &asString); err == nil && strings.TrimSpace(asString) != "" {
			return strings.TrimSpace(asString)
		}
		trimmed := strings.TrimSpace(string(field))
		if strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") {
			return trimmed
		}
	}
	return raw
}

func extractJSONObject(text string) string {
	// Strip markdown ```json ... ``` fences if present.
	cleaned := strings.TrimSpace(text)
	if strings.HasPrefix(cleaned, "```") {
		if idx := strings.Index(cleaned, "\n"); idx >= 0 {
			cleaned = cleaned[idx+1:]
		}
		if end := strings.LastIndex(cleaned, "```"); end >= 0 {
			cleaned = cleaned[:end]
		}
		cleaned = strings.TrimSpace(cleaned)
	}
	// Find the last balanced top-level JSON object (agents often emit logs/status
	// before printing the final JSON solution).
	best := ""
	depth := 0
	start := -1
	inString := false
	escaped := false
	for i := 0; i < len(cleaned); i++ {
		ch := cleaned[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					candidate := cleaned[start : i+1]
					if json.Valid([]byte(candidate)) {
						best = candidate
					}
					start = -1
				}
			}
		}
	}
	return best
}
