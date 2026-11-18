package triage

import (
	"context"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanner"
)

// Every category the scanner can emit must have a rule of its own: a finding
// that falls through to the generic rule reaches an operator with no analysis.
func TestRuleProviderCoversEveryScannerCategory(t *testing.T) {
	generic := ruleSpecFor("category-without-a-rule").summary
	for _, category := range scanner.AllIssueCategories() {
		t.Run(string(category), func(t *testing.T) {
			diagnosis, err := NewRuleBasedProvider("fixture-secret").Diagnose(context.Background(), &scanner.Issue{
				ID:        "fixture/" + string(category),
				Namespace: "sre-fixtures",
				Kind:      "Pod",
				Name:      "fixture",
				Category:  category,
				Severity:  scanner.SeverityMedium,
			})
			if err != nil {
				t.Fatalf("Diagnose() error = %v", err)
			}
			if diagnosis == nil || diagnosis.Summary == "" || diagnosis.RootCause == "" || diagnosis.RemediationPlan == "" || diagnosis.ActionType == "" || diagnosis.ProposedCommand == "" || diagnosis.ConfidenceScore <= 0 || diagnosis.ConfidenceScore > 1 {
				t.Fatalf("incomplete diagnosis: %#v", diagnosis)
			}
			if strings.HasPrefix(diagnosis.Summary, generic) {
				t.Fatalf("category %s has no rule of its own: %#v", category, diagnosis)
			}
			if err := ValidateDiagnosis(diagnosis, "fixture/"+string(category)); err != nil {
				t.Fatalf("ValidateDiagnosis() error = %v, diagnosis = %#v", err, diagnosis)
			}
		})
	}
}

func TestRuleProviderTellsOutageFromOrphanedService(t *testing.T) {
	const routed = "Service selector map[app:web] matches 0 running, ready pods. Ingress impact: " + scanner.ServiceRoutedByIngressMarker + " web; active traffic will fail with 502/connection refused."
	const orphaned = "Service selector map[app:keycloak] matches 0 running, ready pods. Ingress impact: no Ingress in namespace keycloak targets keycloak. Active sibling Service(s) with ready endpoints: keycloak-keycloak (1 ready) (" + scanner.ServiceLikelyOrphanedMarker + "; verify internal callers before cleanup)."
	const unknown = "Service selector map[app:api] matches 0 running, ready pods. Ingress impact: lookup unavailable; active client traffic will fail with 502/connection refused if referenced."

	diagnose := func(t *testing.T, details string) *Diagnosis {
		t.Helper()
		diagnosis, err := NewRuleBasedProvider().Diagnose(context.Background(), &scanner.Issue{
			ID: "service-no-endpoints", Namespace: "apps", Kind: "Service", Name: "web",
			Category: scanner.CategoryServiceNoEndpoint, Severity: scanner.SeverityHigh, Details: details,
		})
		if err != nil {
			t.Fatalf("Diagnose() error = %v", err)
		}
		if !strings.HasSuffix(diagnosis.RootCause, "Evidence: "+details) {
			t.Fatalf("root cause dropped the scanner evidence: %q", diagnosis.RootCause)
		}
		return diagnosis
	}

	outage := diagnose(t, routed)
	if !strings.Contains(outage.RootCause, "failing now") || !strings.Contains(outage.RemediationPlan, "Restore the backend") {
		t.Fatalf("Ingress-routed Service was not diagnosed as an outage: %#v", outage)
	}
	leftover := diagnose(t, orphaned)
	if !strings.Contains(leftover.RootCause, "leftover Service rather than an outage") || !strings.Contains(leftover.RemediationPlan, "remove it") {
		t.Fatalf("unreferenced Service was not diagnosed as orphaned: %#v", leftover)
	}
	// A failed Ingress lookup proves nothing, so the general rule must stand.
	general := ruleSpecFor(scanner.CategoryServiceNoEndpoint)
	if undecided := diagnose(t, unknown); !strings.HasPrefix(undecided.RootCause, general.rootCause) || undecided.RemediationPlan != general.remediation {
		t.Fatalf("an unknown Ingress impact was diagnosed as decided: %#v", undecided)
	}
}

func TestRuleProviderQuotesEventsWhenFindingHasNoDetails(t *testing.T) {
	diagnosis, err := NewRuleBasedProvider().Diagnose(context.Background(), &scanner.Issue{
		ID: "warning-event", Namespace: "apps", Kind: "Pod", Name: "web",
		Category: scanner.CategoryWarningEvent, Severity: scanner.SeverityHigh,
		Events: []string{"first", "second", "third", "fourth"},
	})
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	if !strings.HasSuffix(diagnosis.RootCause, "Events: first; second; third") {
		t.Fatalf("root cause = %q, want the first %d events as evidence", diagnosis.RootCause, maxRuleEvidenceEvents)
	}
}
