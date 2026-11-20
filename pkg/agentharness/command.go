package agentharness

import (
	"fmt"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
)

const solutionJSONSchema = `{"type":"object","required":["summary","root_cause","remediation_plan","action_type","proposed_commands","verification_plan","rollback_plan","confidence_score"],"properties":{"summary":{"type":"string"},"root_cause":{"type":"string"},"remediation_plan":{"type":"string"},"action_type":{"type":"string","enum":["AgentRemediation","GitOpsPR","RestartPod","RolloutRestart","ScaleWorkload","Manual"]},"proposed_commands":{"type":"array","items":{"type":"string"}},"gitops_patch":{"type":"string"},"verification_plan":{"type":"string"},"rollback_plan":{"type":"string"},"confidence_score":{"type":"number","minimum":0,"maximum":1}}}`

// CommandSpec is a concrete, injection-safe invocation of a harness CLI.
type CommandSpec struct {
	Binary     string
	Args       []string
	UseStdin   bool
	PromptText string
}

// BuildCommandSpec builds the exact CLI command for either `codex` (default)
// or `agy` in the requested phase (`plan` read-only vs `apply` write).
func BuildCommandSpec(cfg Config, harness HarnessKind, phase Phase, prompt string) (CommandSpec, error) {
	norm := cfg.Normalized()
	kind, err := ParseHarnessKind(string(harness))
	if err != nil {
		return CommandSpec{}, err
	}
	switch phase {
	case PhasePlan, PhaseApply:
	default:
		return CommandSpec{}, fmt.Errorf("unsupported agent phase %q", phase)
	}

	switch kind {
	case HarnessCodex:
		sandboxFlag := "read-only"
		if phase == PhaseApply {
			sandboxFlag = "workspace-write"
		}
		args := []string{"exec", "--sandbox", sandboxFlag}
		if model := strings.TrimSpace(norm.Model); model != "" {
			args = append(args, "--model", model)
		}
		if effort := strings.TrimSpace(norm.ReasoningEffort); effort != "" {
			args = append(args, "-c", fmt.Sprintf("model_reasoning_effort=%q", effort))
		}
		// Read the prompt from stdin (`-`) to keep prompts out of process args.
		args = append(args, "-")
		return CommandSpec{
			Binary:     norm.CodexBinary,
			Args:       args,
			UseStdin:   true,
			PromptText: prompt,
		}, nil

	case HarnessAgy:
		mode := "plan"
		if phase == PhaseApply {
			mode = "accept-edits"
		}
		args := []string{"--print", "--mode", mode, "--sandbox", "--output-format", "json"}
		if phase == PhasePlan {
			args = append(args, "--json-schema", solutionJSONSchema)
		}
		if model := strings.TrimSpace(norm.Model); model != "" {
			args = append(args, "--model", model)
		}
		if effort := strings.TrimSpace(norm.ReasoningEffort); effort != "" {
			args = append(args, "--effort", effort)
		}
		return CommandSpec{
			Binary:     norm.AgyBinary,
			Args:       args,
			UseStdin:   true,
			PromptText: prompt,
		}, nil
	default:
		return CommandSpec{}, fmt.Errorf("unsupported agent harness %q", kind)
	}
}

// BuildContainerCommand wraps the harness command inside a Kubernetes sandbox
// container so the prompt is loaded from a mounted read-only file rather than
// exposed in pod spec args.
func BuildContainerCommand(cfg Config, harness HarnessKind, phase Phase, promptFilePath string) ([]string, error) {
	spec, err := BuildCommandSpec(cfg, harness, phase, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(promptFilePath) == "" {
		promptFilePath = "/etc/sre-solver/prompt.txt"
	}
	if harness == HarnessAgy {
		// `agy --print` reads its prompt from positional text or stdin; pass
		// file content via shell redirection so nothing leaks in argv.
		quotedArgs := shellJoin(append([]string{spec.Binary}, spec.Args...))
		return []string{"/bin/sh", "-ec", fmt.Sprintf("exec %s < %s", quotedArgs, shellQuote(promptFilePath))}, nil
	}
	// `codex exec ... -` reads prompt directly from stdin.
	quotedArgs := shellJoin(append([]string{spec.Binary}, spec.Args...))
	return []string{"/bin/sh", "-ec", fmt.Sprintf("exec %s < %s", quotedArgs, shellQuote(promptFilePath))}, nil
}

// BuildPlanPrompt builds the read-only investigation & solution-creation prompt
// for Phase 1.
func BuildPlanPrompt(issue *scanner.Issue, gitopsRepo string, secretValues ...string) string {
	redactor := sanitizer.RedactorForSecrets(secretValues...)
	var b strings.Builder
	b.WriteString("You are Kubebee SRE's autonomous investigation agent running in READ-ONLY planning mode.\n")
	b.WriteString("DO NOT mutate the Kubernetes cluster, delete resources, or push commits.\n")
	b.WriteString("Inspect the cluster using read-only kubectl commands (get, describe, logs, events) to find the verified root cause and produce a concrete, minimal, safe remediation solution for human approval.\n\n")
	if strings.TrimSpace(gitopsRepo) != "" {
		b.WriteString("GitOps repository: " + redactor.SanitizeText(gitopsRepo) + "\n\n")
	}
	if issue != nil {
		b.WriteString("=== ISSUE CONTEXT ===\n")
		b.WriteString(fmt.Sprintf("ID: %s\n", redactor.SanitizeText(issue.ID)))
		b.WriteString(fmt.Sprintf("Namespace: %s\n", redactor.SanitizeText(issue.Namespace)))
		b.WriteString(fmt.Sprintf("Resource: %s/%s\n", redactor.SanitizeText(issue.Kind), redactor.SanitizeText(issue.Name)))
		b.WriteString(fmt.Sprintf("Category: %s | Severity: %s\n", redactor.SanitizeText(string(issue.Category)), redactor.SanitizeText(string(issue.Severity))))
		b.WriteString(fmt.Sprintf("Summary: %s\n", redactor.SanitizeText(issue.Summary)))
		if strings.TrimSpace(issue.Details) != "" {
			b.WriteString(fmt.Sprintf("Details:\n%s\n", redactor.SanitizeText(issue.Details)))
		}
		if strings.TrimSpace(issue.LogsSnippet) != "" {
			b.WriteString(fmt.Sprintf("Recent Logs:\n%s\n", redactor.SanitizeText(issue.LogsSnippet)))
		}
		if len(issue.Events) > 0 {
			b.WriteString("Recent Events:\n")
			for _, ev := range issue.Events {
				b.WriteString("- " + redactor.SanitizeText(ev) + "\n")
			}
		}
		b.WriteString("=====================\n\n")
	}
	b.WriteString("Return ONLY a single valid JSON object matching this schema:\n")
	b.WriteString(solutionJSONSchema + "\n")
	b.WriteString("Use action_type=\"AgentRemediation\" when executing the proposed_commands/gitops_patch requires agent execution upon human approval.\n")
	return b.String()
}

// BuildApplyPrompt builds the approval-scoped execution prompt for Phase 2.
func BuildApplyPrompt(req ApplyRequest, gitopsRepo string, secretValues ...string) string {
	redactor := sanitizer.RedactorForSecrets(secretValues...)
	var b strings.Builder
	b.WriteString("You are Kubebee SRE's execution agent running an EXPLICITLY HUMAN-APPROVED remediation.\n")
	b.WriteString("Execute ONLY the approved plan and commands below. Do not expand scope, force-delete namespaces/PVCs, or touch unrelated workloads.\n\n")
	b.WriteString(fmt.Sprintf("Proposal ID: %s\n", redactor.SanitizeText(req.ProposalID)))
	b.WriteString(fmt.Sprintf("Approved By: %s\n", redactor.SanitizeText(req.ApprovedBy)))
	b.WriteString(fmt.Sprintf("Target: %s %s/%s\n", redactor.SanitizeText(req.Kind), redactor.SanitizeText(req.Namespace), redactor.SanitizeText(req.Name)))
	if strings.TrimSpace(gitopsRepo) != "" {
		b.WriteString(fmt.Sprintf("GitOps Repo: %s\n", redactor.SanitizeText(gitopsRepo)))
	}
	b.WriteString(fmt.Sprintf("\nSummary: %s\n", redactor.SanitizeText(req.Summary)))
	b.WriteString(fmt.Sprintf("Root Cause: %s\n", redactor.SanitizeText(req.RootCause)))
	b.WriteString(fmt.Sprintf("Approved Plan:\n%s\n", redactor.SanitizeText(req.RemediationPlan)))
	if len(req.ProposedCommands) > 0 {
		b.WriteString("\nApproved Commands:\n")
		for i, cmd := range req.ProposedCommands {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, redactor.SanitizeText(cmd)))
		}
	} else if strings.TrimSpace(req.ProposedCommand) != "" {
		b.WriteString(fmt.Sprintf("\nApproved Command:\n%s\n", redactor.SanitizeText(req.ProposedCommand)))
	}
	if strings.TrimSpace(req.GitOpsPatch) != "" {
		b.WriteString(fmt.Sprintf("\nApproved GitOps Patch:\n%s\n", redactor.SanitizeText(req.GitOpsPatch)))
	}
	if strings.TrimSpace(req.VerificationPlan) != "" {
		b.WriteString(fmt.Sprintf("\nVerification Steps:\n%s\n", redactor.SanitizeText(req.VerificationPlan)))
	}
	if strings.TrimSpace(req.RollbackPlan) != "" {
		b.WriteString(fmt.Sprintf("\nRollback Plan (if verification fails):\n%s\n", redactor.SanitizeText(req.RollbackPlan)))
	}
	b.WriteString("\nAfter executing and verifying, output a concise summary of actions taken and verification results.\n")
	return b.String()
}

func shellJoin(parts []string) string {
	quoted := make([]string, len(parts))
	for i, p := range parts {
		quoted[i] = shellQuote(p)
	}
	return strings.Join(quoted, " ")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
