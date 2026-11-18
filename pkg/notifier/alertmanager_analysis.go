package notifier

import (
	"fmt"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

const (
	maxAlertAnalysisBytes  = 1536
	maxAlertActionBytes    = 1024
	maxAlertScopeResources = 5
)

// alertAnalysis is the root cause a diagnosis gives for a finding, followed by
// the finding's scope unless the root cause already quotes the scanner's
// details, which state it.
func alertAnalysis(redactor *sanitizer.Redactor, issue *scanner.Issue, diagnosis *triage.Diagnosis) string {
	if diagnosis == nil {
		return ""
	}
	analysis := strings.TrimSpace(redactor.SanitizeText(diagnosis.RootCause))
	if analysis == "" {
		analysis = strings.TrimSpace(redactor.SanitizeText(diagnosis.Summary))
	}
	if details := alertDetails(redactor, issue); details == "" || !strings.Contains(analysis, details) {
		analysis = strings.TrimSpace(analysis + " " + alertScope(redactor, issue))
	}
	return truncateUTF8(analysis, maxAlertAnalysisBytes)
}

// alertScope states how widely a folded finding occurs.
func alertScope(redactor *sanitizer.Redactor, issue *scanner.Issue) string {
	if issue.OccurrenceCount <= 1 {
		return ""
	}
	affected := issue.AffectedResources
	if len(affected) == 0 {
		return fmt.Sprintf("Scope: %d occurrences.", issue.OccurrenceCount)
	}
	more := ""
	if hidden := len(affected) - maxAlertScopeResources; hidden > 0 {
		affected = affected[:maxAlertScopeResources]
		more = fmt.Sprintf(" and %d more", hidden)
	}
	return fmt.Sprintf("Scope: %d occurrences across %s%s.", issue.OccurrenceCount, redactor.SanitizeText(strings.Join(affected, ", ")), more)
}

// alertRecommendedAction is the remediation a diagnosis proposes: its action
// type and plan, and its command when that is more than a comment.
func alertRecommendedAction(redactor *sanitizer.Redactor, diagnosis *triage.Diagnosis) string {
	if diagnosis == nil {
		return ""
	}
	action := strings.TrimSpace(redactor.SanitizeText(diagnosis.RemediationPlan))
	if actionType := strings.TrimSpace(redactor.SanitizeText(string(diagnosis.ActionType))); actionType != "" {
		action = strings.TrimSuffix(actionType+": "+action, ": ")
	}
	if command := strings.TrimSpace(redactor.SanitizeText(diagnosis.ProposedCommand)); command != "" && !strings.HasPrefix(command, "#") {
		action = strings.TrimSpace(action + " Proposed command: " + command)
	}
	return truncateUTF8(action, maxAlertActionBytes)
}

// alertDescription leads with the analysis and the recommended action, so that
// they survive truncation, and follows with the scanner's evidence. Details
// that the analysis already quotes are not repeated.
func alertDescription(redactor *sanitizer.Redactor, issue *scanner.Issue, analysis, recommendedAction string) string {
	var sections []string
	if analysis != "" {
		sections = append(sections, "Analysis: "+analysis)
	}
	if recommendedAction != "" {
		sections = append(sections, "Recommended action: "+recommendedAction)
	}
	if details := alertDetails(redactor, issue); details != "" && !strings.Contains(analysis, details) {
		sections = append(sections, details)
	}
	if len(issue.AffectedResources) > 0 {
		sections = append(sections, "Affected resources: "+redactor.SanitizeText(strings.Join(issue.AffectedResources, ", ")))
	}
	if logs := strings.TrimSpace(redactor.SanitizeText(issue.LogsSnippet)); logs != "" {
		sections = append(sections, "Recent failure logs:\n"+logs)
	}
	return truncateUTF8(strings.Join(sections, "\n"), maxAlertmanagerDescBytes)
}

func alertDetails(redactor *sanitizer.Redactor, issue *scanner.Issue) string {
	return strings.TrimSpace(redactor.SanitizeText(issue.Details))
}
