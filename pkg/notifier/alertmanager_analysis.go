package notifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

const (
	// alertDiagnosisTTL is how long a diagnosis is reused for a finding whose
	// evidence has not changed, before a fresh one is worth asking for.
	alertDiagnosisTTL      = 6 * time.Hour
	maxAlertDiagnoses      = 512
	maxAlertAnalysisBytes  = 1536
	maxAlertActionBytes    = 1024
	maxAlertScopeResources = 5
)

// alertDiagnosis is the diagnosis recorded for one alert. It stands for as
// long as the finding's evidence still matches fingerprint.
type alertDiagnosis struct {
	fingerprint string
	diagnosis   *triage.Diagnosis
	recordedAt  time.Time
}

// RecordDiagnosis keeps a sanitized copy of the diagnosis of an alertable
// finding. SyncFoldedIssues annotates the finding's alert with it, and
// CachedDiagnosis returns it on later scans, until the finding's evidence
// changes, its alert resolves, or alertDiagnosisTTL passes.
func (n *AlertmanagerNotifier) RecordDiagnosis(issue *scanner.Issue, diagnosis *triage.Diagnosis) {
	if !n.Enabled() || diagnosis == nil || !n.IsAlertableIssue(issue) {
		return
	}
	key := n.alertKey(issue)
	entry := alertDiagnosis{
		fingerprint: evidenceFingerprint(issue),
		diagnosis:   n.sanitizedDiagnosis(diagnosis),
		recordedAt:  n.now(),
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if _, known := n.diagnoses[key]; !known && len(n.diagnoses) >= maxAlertDiagnoses {
		n.evictDiagnosisLocked(entry.recordedAt)
	}
	n.diagnoses[key] = entry
}

// CachedDiagnosis returns the diagnosis recorded for a finding, provided the
// finding's evidence is unchanged since it was recorded.
func (n *AlertmanagerNotifier) CachedDiagnosis(issue *scanner.Issue) (*triage.Diagnosis, bool) {
	if !n.Enabled() || issue == nil {
		return nil, false
	}
	key := n.alertKey(issue)
	n.mu.Lock()
	entry, found := n.diagnoses[key]
	n.mu.Unlock()
	if !found || entry.fingerprint != evidenceFingerprint(issue) || n.now().Sub(entry.recordedAt) >= alertDiagnosisTTL {
		return nil, false
	}
	return n.sanitizedDiagnosis(entry.diagnosis), true
}

// evictDiagnosisLocked makes room for one more diagnosis: it drops every
// expired entry and, when none has expired, the oldest one.
func (n *AlertmanagerNotifier) evictDiagnosisLocked(now time.Time) {
	oldestKey := ""
	var oldest time.Time
	for key, entry := range n.diagnoses {
		if now.Sub(entry.recordedAt) >= alertDiagnosisTTL {
			delete(n.diagnoses, key)
			continue
		}
		if oldestKey == "" || entry.recordedAt.Before(oldest) || (entry.recordedAt.Equal(oldest) && key < oldestKey) {
			oldestKey, oldest = key, entry.recordedAt
		}
	}
	if len(n.diagnoses) >= maxAlertDiagnoses {
		delete(n.diagnoses, oldestKey)
	}
}

// sanitizedDiagnosis returns a redacted copy, so that neither the cache nor a
// caller shares memory with a provider's result.
func (n *AlertmanagerNotifier) sanitizedDiagnosis(diagnosis *triage.Diagnosis) *triage.Diagnosis {
	return diagnosis.SanitizedWithRedactor(n.redactorOrDefault()).AsDiagnosis()
}

// evidenceFingerprint identifies the evidence a provider is shown for a
// finding. Observation times and the target's resourceVersion are left out on
// purpose: analyzers stamp them on every scan and status heartbeats bump them
// without changing what there is to diagnose, so keying on them would diagnose
// an unchanged finding again on every scan.
func evidenceFingerprint(issue *scanner.Issue) string {
	hash := sha256.New()
	write := func(values ...string) {
		for _, value := range values {
			_, _ = io.WriteString(hash, strconv.Itoa(len(value))+":"+value)
		}
	}
	write(issue.ID, issue.Namespace, issue.Kind, issue.Name, string(issue.Severity), string(issue.Category),
		issue.Summary, issue.Details, issue.LogsSnippet, issue.SpecSnippet)
	write(issue.Events...)
	return hex.EncodeToString(hash.Sum(nil))
}

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
