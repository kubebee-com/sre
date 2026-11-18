package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

func TestNewAlertmanagerNotifierNormalizesEndpointAndRejectsInvalid(t *testing.T) {
	am, err := NewAlertmanagerNotifier(AlertmanagerOptions{
		Endpoint:  "http://monitoring-alertmanager.monitoring.svc.cluster.local:9093",
		PublicURL: "https://sre.example.com",
	})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	if !am.Enabled() {
		t.Fatal("expected AlertmanagerNotifier to be enabled")
	}
	want := "http://monitoring-alertmanager.monitoring.svc.cluster.local:9093/api/v2/alerts"
	if am.endpoint != want {
		t.Fatalf("endpoint = %q, want %q", am.endpoint, want)
	}

	for _, bad := range []string{
		"ftp://alertmanager.invalid",
		"http://user:pass@alertmanager.invalid:9093",
		"http://alertmanager.invalid:9093\r\nX-Injected: true",
	} {
		if _, err := NewAlertmanagerNotifier(AlertmanagerOptions{Endpoint: bad}); err == nil {
			t.Errorf("expected invalid Alertmanager endpoint %q to fail", bad)
		}
	}
}

func TestAlertmanagerNotifierSyncsFoldedSeriousAlertsFiltersPostureAndResolves(t *testing.T) {
	var (
		mu       sync.Mutex
		requests [][]alertmanagerAlert
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			t.Errorf("unexpected path = %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var decoded []alertmanagerAlert
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("decode alert payload: %v", err)
		}
		mu.Lock()
		requests = append(requests, decoded)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	am, err := NewAlertmanagerNotifier(AlertmanagerOptions{
		Endpoint:     ts.URL,
		MinSeverity:  "HIGH",
		PublicURL:    "https://sre.example.com",
		SecretValues: []string{"super-secret-token"},
	})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	now := time.Date(2026, 11, 18, 7, 0, 0, 0, time.UTC)
	am.now = func() time.Time { return now }

	issues := []*scanner.Issue{
		{
			ID:                "ingress-nginx/Service/ingress-nginx-controller/HealthCheck",
			Namespace:         "ingress-nginx",
			Kind:              "Service",
			Name:              "ingress-nginx-controller",
			Severity:          scanner.SeverityCritical,
			Category:          scanner.CategoryServiceHealthCheck,
			Group:             scanner.GroupFailures,
			Summary:           "Service ingress-nginx-controller healthCheckNodePort 31543 is disabled by Cilium CNI config",
			Details:           "token=super-secret-token Cilium enable-health-check-nodeport=false",
			FoldKey:           "fold-svc-health",
			OccurrenceCount:   1,
			AffectedResources: []string{"ingress-nginx/ingress-nginx-controller"},
		},
		{
			// Passive security posture should not page when IncludePosture is false.
			Namespace: "kube-system", Kind: "Pod", Name: "cilium-1",
			Severity: scanner.SeverityCritical, Category: scanner.CategorySecurityClusterBinding,
			Summary: "system cluster-admin", FoldKey: "fold-rbac",
		},
		{
			// Medium severity below HIGH threshold should not page.
			Namespace: "default", Kind: "Pod", Name: "web-0",
			Severity: scanner.SeverityMedium, Category: scanner.CategoryPodLogError,
			Summary: "minor error", FoldKey: "fold-med",
		},
	}

	if err := am.SyncFoldedIssues(context.Background(), issues, nil, true); err != nil {
		t.Fatalf("SyncFoldedIssues(initial) error = %v", err)
	}

	// Partial scoped scan for another namespace must NOT resolve the existing alert.
	now = now.Add(time.Minute)
	otherHigh := []*scanner.Issue{{
		ID: "ctrl/Pod/sync/Log", Namespace: "cluster-config-controller", Kind: "Pod", Name: "cluster-sync-controller-0",
		Severity: scanner.SeverityHigh, Category: scanner.CategoryPodLogError, Group: scanner.GroupErrors,
		Summary: "unable to construct NLB client", Details: "OCI NLB discovery failed",
		LogsSnippet: "unable to construct NLB client", FoldKey: "fold-ctrl-log", OccurrenceCount: 2,
		Parent: &scanner.ResourceRef{Namespace: "cluster-config-controller", Kind: "Deployment", Name: "cluster-sync-controller"},
	}}
	if err := am.SyncFoldedIssues(context.Background(), otherHigh, nil, false); err != nil {
		t.Fatalf("SyncFoldedIssues(partial) error = %v", err)
	}

	// Full cluster scan returning empty clears BOTH active alerts with EndsAt == now.
	now = now.Add(time.Minute)
	if err := am.SyncFoldedIssues(context.Background(), nil, nil, true); err != nil {
		t.Fatalf("SyncFoldedIssues(resolved) error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("alertmanager received %d POSTs, want 3", len(requests))
	}
	if len(requests[0]) != 1 {
		t.Fatalf("first POST sent %d alerts, want 1 filtered alert: %#v", len(requests[0]), requests[0])
	}
	first := requests[0][0]
	if first.Labels["component"] != "kubebee-sre" || first.Labels["severity"] != "critical" {
		t.Fatalf("unexpected alert labels: %#v", first.Labels)
	}
	if strings.Contains(first.Annotations["description"], "super-secret-token") {
		t.Fatalf("alert leaked configured secret: %s", first.Annotations["description"])
	}
	if !first.EndsAt.After(first.StartsAt) {
		t.Fatalf("firing alert EndsAt (%s) <= StartsAt (%s)", first.EndsAt, first.StartsAt)
	}
	if len(requests[2]) != 2 {
		t.Fatalf("resolved POST sent %d alerts, want 2 resolved alerts", len(requests[2]))
	}
	for _, resolved := range requests[2] {
		if !resolved.EndsAt.Equal(now) {
			t.Fatalf("resolved alert %s EndsAt = %s, want %s", resolved.Labels["fold_key"], resolved.EndsAt, now)
		}
	}
}

// alertSink is an Alertmanager stand-in that records every posted batch.
type alertSink struct {
	mu      sync.Mutex
	batches [][]alertmanagerAlert
}

func newAlertSink(t *testing.T) (*alertSink, string) {
	t.Helper()
	sink := &alertSink{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []alertmanagerAlert
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode alert payload: %v", err)
		}
		sink.mu.Lock()
		sink.batches = append(sink.batches, batch)
		sink.mu.Unlock()
	}))
	t.Cleanup(server.Close)
	return sink, server.URL
}

// lastByFoldKey returns the alerts of the most recent batch by fold_key label.
func (s *alertSink) lastByFoldKey(t *testing.T) map[string]alertmanagerAlert {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.batches) == 0 {
		t.Fatal("Alertmanager received no alerts")
	}
	alerts := make(map[string]alertmanagerAlert)
	for _, alert := range s.batches[len(s.batches)-1] {
		alerts[alert.Labels["fold_key"]] = alert
	}
	return alerts
}

func TestAlertmanagerNotifierAlertsOncePerEligibleFinding(t *testing.T) {
	am, err := NewAlertmanagerNotifier(AlertmanagerOptions{Endpoint: "http://alertmanager.invalid:9093", MinSeverity: "HIGH"})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	folded := []*scanner.Issue{
		nil,
		{ID: "critical", Severity: scanner.SeverityCritical, Category: scanner.CategoryCrashLoop, FoldKey: "fold-crash"},
		{ID: "same-alert", Severity: scanner.SeverityCritical, Category: scanner.CategoryCrashLoop, FoldKey: "fold-crash"},
		{ID: "posture", Severity: scanner.SeverityCritical, Category: scanner.CategorySecurityClusterBinding, FoldKey: "fold-posture"},
		{ID: "medium", Severity: scanner.SeverityMedium, Category: scanner.CategoryPodLogError, FoldKey: "fold-medium"},
		{ID: "high", Severity: scanner.SeverityHigh, Category: scanner.CategoryServiceNoEndpoint, FoldKey: "fold-service"},
	}

	eligible := am.eligibleIssues(folded)
	if len(eligible) != 2 || eligible[0] != folded[1] || eligible[1] != folded[5] {
		t.Fatalf("eligibleIssues() = %#v, want the critical and the high finding, once each", eligible)
	}

	// The alert policy holds without an Alertmanager too: it decides which
	// findings are serious enough to be diagnosed by a model.
	var unconfigured *AlertmanagerNotifier
	if !unconfigured.IsAlertableIssue(folded[1]) || unconfigured.IsAlertableIssue(folded[3]) || unconfigured.IsAlertableIssue(folded[4]) {
		t.Fatal("the default alert policy must pass HIGH and above and hold back posture findings")
	}
	if err := unconfigured.SyncFoldedIssues(context.Background(), folded, nil, true); err != nil {
		t.Fatalf("SyncFoldedIssues() without Alertmanager error = %v", err)
	}
}

func TestAlertmanagerNotifierAnnotatesAlertWithItsDiagnosis(t *testing.T) {
	const secret = "diagnosis-secret-0123456789"
	sink, endpoint := newAlertSink(t)
	am, err := NewAlertmanagerNotifier(AlertmanagerOptions{Endpoint: endpoint, SecretValues: []string{secret}})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}

	diagnosed := &scanner.Issue{
		ID: "prod/Pod/worker-0/CrashLoop", Namespace: "prod", Kind: "Pod", Name: "worker-0",
		Severity: scanner.SeverityCritical, Category: scanner.CategoryCrashLoop,
		Summary:           "Pod worker-0 is in CrashLoopBackOff",
		Details:           "Container exited with code 137 token=" + secret,
		LogsSnippet:       strings.Repeat("panic: out of memory\n", 400),
		FoldKey:           "fold-diagnosed",
		OccurrenceCount:   3,
		AffectedResources: []string{"prod/worker-0", "prod/worker-1", "prod/worker-2"},
	}
	undiagnosed := *diagnosed
	undiagnosed.FoldKey = "fold-undiagnosed"

	diagnoses := map[*scanner.Issue]*triage.Diagnosis{diagnosed: {
		IssueID:         diagnosed.ID,
		Summary:         "Worker runs out of memory",
		RootCause:       "The worker exceeds its memory limit while loading " + secret + ".",
		RemediationPlan: "Raise the memory limit and stop logging " + secret + ".",
		ActionType:      triage.ActionGitOpsPR,
		ProposedCommand: "kubectl describe pod worker-0 -n prod",
		// A provider's view of severity must never reach the alert's labels.
		Severity:        scanner.SeverityLow,
		ConfidenceScore: 0.9,
		ProviderName:    "test-provider",
	}}
	if err := am.SyncFoldedIssues(context.Background(), []*scanner.Issue{diagnosed, &undiagnosed}, diagnoses, true); err != nil {
		t.Fatalf("SyncFoldedIssues() error = %v", err)
	}
	alerts := sink.lastByFoldKey(t)
	annotated, plain := alerts["fold-diagnosed"], alerts["fold-undiagnosed"]

	analysis := annotated.Annotations["analysis"]
	if !strings.HasPrefix(analysis, "The worker exceeds its memory limit while loading ") ||
		!strings.HasSuffix(analysis, " Scope: 3 occurrences across prod/worker-0, prod/worker-1, prod/worker-2.") {
		t.Fatalf("analysis = %q, want the root cause followed by the finding's scope", analysis)
	}
	action := annotated.Annotations["recommended_action"]
	if !strings.HasPrefix(action, "GitOpsPR: Raise the memory limit") || !strings.HasSuffix(action, " Proposed command: kubectl describe pod worker-0 -n prod") {
		t.Fatalf("recommended_action = %q, want action type, plan, and proposed command", action)
	}
	if annotated.Annotations["triage_provider"] != "test-provider" {
		t.Fatalf("triage_provider = %q, want test-provider", annotated.Annotations["triage_provider"])
	}

	// The analysis leads the description so that long evidence cannot push it
	// past the size bound, and the scanner's own details are still there.
	description := annotated.Annotations["description"]
	if len(description) > maxAlertmanagerDescBytes {
		t.Fatalf("description is %d bytes, over the %d byte bound", len(description), maxAlertmanagerDescBytes)
	}
	for _, want := range []string{"Analysis: " + analysis + "\n", "Recommended action: " + action + "\n", "\nContainer exited with code 137", "\nRecent failure logs:\n"} {
		if !strings.Contains(description, want) {
			t.Fatalf("description lacks %q:\n%s", want, description)
		}
	}
	if !strings.HasPrefix(description, "Analysis: ") {
		t.Fatalf("description does not lead with the analysis:\n%s", description)
	}

	// Without a diagnosis the alert is sent exactly as the scanner found it.
	for _, annotation := range []string{"analysis", "recommended_action", "triage_provider"} {
		if value, present := plain.Annotations[annotation]; present {
			t.Fatalf("undiagnosed alert has %s = %q", annotation, value)
		}
	}
	if !strings.HasPrefix(plain.Annotations["description"], "Container exited with code 137") {
		t.Fatalf("undiagnosed description = %q, want the scanner details first", plain.Annotations["description"])
	}

	// A diagnosis adds annotations only: every label but the alert key agrees.
	for label, value := range plain.Labels {
		if label != "fold_key" && annotated.Labels[label] != value {
			t.Fatalf("diagnosis changed label %s from %q to %q", label, value, annotated.Labels[label])
		}
	}
	if len(annotated.Labels) != len(plain.Labels) || annotated.Labels["severity"] != "critical" {
		t.Fatalf("diagnosis changed the alert labels: %#v", annotated.Labels)
	}
	for _, alert := range alerts {
		for annotation, value := range alert.Annotations {
			if strings.Contains(value, secret) {
				t.Fatalf("annotation %s leaked a configured secret: %q", annotation, value)
			}
		}
	}
}

func TestAlertmanagerNotifierDoesNotRepeatDetailsQuotedByAnalysis(t *testing.T) {
	sink, endpoint := newAlertSink(t)
	am, err := NewAlertmanagerNotifier(AlertmanagerOptions{Endpoint: endpoint})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	const details = "Service selector map[app:keycloak] matches 0 running, ready pods. Ingress impact: no Ingress in namespace keycloak targets keycloak. " +
		"Active sibling Service(s) with ready endpoints: keycloak-keycloak (1 ready) (" + scanner.ServiceLikelyOrphanedMarker + "; verify internal callers before cleanup)."
	issue := &scanner.Issue{
		ID: "keycloak/Service/keycloak/NoEndpoints", Namespace: "keycloak", Kind: "Service", Name: "keycloak",
		Severity: scanner.SeverityHigh, Category: scanner.CategoryServiceNoEndpoint,
		Summary: "Service keycloak has no ready endpoints", Details: details,
		FoldKey: "fold-keycloak", OccurrenceCount: 1, AffectedResources: []string{"keycloak/keycloak"},
	}
	// The rule engine quotes the scanner's details as its evidence.
	diagnosis, err := triage.NewRuleBasedProvider().Diagnose(context.Background(), issue)
	if err != nil {
		t.Fatalf("Diagnose() error = %v", err)
	}
	diagnoses := map[*scanner.Issue]*triage.Diagnosis{issue: diagnosis}
	if err := am.SyncFoldedIssues(context.Background(), []*scanner.Issue{issue}, diagnoses, true); err != nil {
		t.Fatalf("SyncFoldedIssues() error = %v", err)
	}
	annotations := sink.lastByFoldKey(t)["fold-keycloak"].Annotations

	if !strings.Contains(annotations["analysis"], "leftover Service rather than an outage") || !strings.HasSuffix(annotations["analysis"], details) {
		t.Fatalf("analysis = %q, want the orphaned-Service root cause with the scanner evidence", annotations["analysis"])
	}
	if got := strings.Count(annotations["description"], details); got != 1 {
		t.Fatalf("description quotes the scanner details %d times, want once:\n%s", got, annotations["description"])
	}
	want := "Manual: Confirm that no in-cluster client still calls this Service, then remove it or correct its selector through the deployment source. Proposed command: kubectl describe service keycloak -n keycloak"
	if annotations["recommended_action"] != want {
		t.Fatalf("recommended_action = %q, want %q", annotations["recommended_action"], want)
	}
	if annotations["triage_provider"] != "Rule-Based SRE Engine" {
		t.Fatalf("triage_provider = %q", annotations["triage_provider"])
	}
}

func TestTruncateUTF8KeepsWholeRunes(t *testing.T) {
	for _, test := range []struct {
		value string
		max   int
		want  string
	}{
		{"short", 16, "short"},
		{"exactly8", 8, "exactly8"},
		{"ééé", 3, "é"},
		{"a€b", 3, "a"},
		{"a€b", 4, "a€"},
	} {
		if got := truncateUTF8(test.value, test.max); got != test.want {
			t.Errorf("truncateUTF8(%q, %d) = %q, want %q", test.value, test.max, got, test.want)
		}
	}
}
