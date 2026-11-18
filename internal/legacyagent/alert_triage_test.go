package legacyagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	serverpkg "github.com/kubebee-com/sre/internal/legacyserver"
	"github.com/kubebee-com/sre/pkg/config"
	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/scanplan"
	"github.com/kubebee-com/sre/pkg/triage"
)

type postedAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// alertmanagerStub stands in for Alertmanager and hands each posted batch to
// the test, so a test can look at an alert while the scan is still running.
type alertmanagerStub struct {
	url     string
	batches chan []postedAlert
}

func newAlertmanagerStub(t *testing.T) *alertmanagerStub {
	t.Helper()
	stub := &alertmanagerStub{batches: make(chan []postedAlert, 16)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []postedAlert
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode alert payload: %v", err)
		}
		stub.batches <- batch
	}))
	t.Cleanup(server.Close)
	stub.url = server.URL
	return stub
}

// next returns the alerts of the next posted batch by resource name.
func (s *alertmanagerStub) next(t *testing.T) map[string]postedAlert {
	t.Helper()
	select {
	case batch := <-s.batches:
		alerts := make(map[string]postedAlert, len(batch))
		for _, alert := range batch {
			alerts[alert.Labels["resource_name"]] = alert
		}
		return alerts
	case <-time.After(10 * time.Second):
		t.Fatal("Alertmanager received no alerts")
		return nil
	}
}

// scriptedProvider counts the diagnoses asked of it and how many overlapped.
type scriptedProvider struct {
	mu       sync.Mutex
	calls    map[string]int
	inFlight int
	peak     int
	diagnose func(context.Context, *scanner.Issue) (*triage.Diagnosis, error)
}

func (p *scriptedProvider) Name() string { return "scripted-provider" }

func (p *scriptedProvider) Diagnose(ctx context.Context, issue *scanner.Issue) (*triage.Diagnosis, error) {
	p.mu.Lock()
	if p.calls == nil {
		p.calls = make(map[string]int)
	}
	p.calls[issue.ID]++
	p.inFlight++
	p.peak = max(p.peak, p.inFlight)
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.inFlight--
		p.mu.Unlock()
	}()
	if p.diagnose != nil {
		return p.diagnose(ctx, issue)
	}
	return restartDiagnosis(issue), nil
}

func (p *scriptedProvider) Explain(context.Context, string, *scanner.Issue) (string, error) {
	return "", nil
}

func (p *scriptedProvider) callsFor(issue *scanner.Issue) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[issue.ID]
}

func (p *scriptedProvider) peakConcurrency() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.peak
}

func (p *scriptedProvider) totalCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, calls := range p.calls {
		total += calls
	}
	return total
}

func restartDiagnosis(issue *scanner.Issue) *triage.Diagnosis {
	return &triage.Diagnosis{
		IssueID:         issue.ID,
		ProviderName:    "scripted-provider",
		Severity:        issue.Severity,
		Summary:         "Diagnosed " + issue.Name,
		RootCause:       "Root cause of " + issue.Name,
		RemediationPlan: "Restart " + issue.Name,
		ActionType:      triage.ActionRestartPod,
		ProposedCommand: "kubectl delete pod " + issue.Name + " -n " + issue.Namespace,
		ConfidenceScore: 0.9,
	}
}

func crashLoopIssue(name string) *scanner.Issue {
	return &scanner.Issue{
		ID: "prod/Pod/" + name + "/CrashLoop", Namespace: "prod", Kind: "Pod", Name: name,
		TargetUID: "uid-" + name, TargetResourceVersion: "1",
		Severity: scanner.SeverityCritical, Category: scanner.CategoryCrashLoop,
		Summary: "Pod " + name + " is in CrashLoopBackOff", Details: "Container of " + name + " exited with code 1",
	}
}

// alertScan wires a scan to an Alertmanager stub the way the agent does.
type alertScan struct {
	cfg      *config.Config
	service  *singleScanService
	provider triage.TriageProvider
	engine   *remediation.Engine
	server   *serverpkg.Server
	alerts   *alertmanagerStub
}

func newAlertScan(t *testing.T, cfg *config.Config, provider triage.TriageProvider, issues ...*scanner.Issue) *alertScan {
	t.Helper()
	alerts := newAlertmanagerStub(t)
	alertmanager, err := notifier.NewAlertmanagerNotifier(notifier.AlertmanagerOptions{
		Endpoint:     alerts.url,
		SecretValues: providerSecretValues(cfg),
	})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	service := &singleScanService{report: &scanner.ScanReport{
		SchemaVersion: scanplan.SchemaVersion,
		Scope:         scanplan.Default().EffectiveScope(),
		Issues:        issues,
	}}
	engine := remediation.NewEngine(nil)
	server := serverpkg.NewServer(0, service, provider, engine, nil, serverpkg.ServerOptions{
		Alertmanager:     alertmanager,
		RedactionSecrets: providerSecretValues(cfg),
	})
	return &alertScan{cfg: cfg, service: service, provider: provider, engine: engine, server: server, alerts: alerts}
}

func (s *alertScan) scan() error {
	return runSingleScan(context.Background(), s.cfg, s.service, s.provider, s.engine, nil, s.server)
}

// run scans once and returns the alerts that scan posted.
func (s *alertScan) run(t *testing.T) map[string]postedAlert {
	t.Helper()
	if err := s.scan(); err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	return s.alerts.next(t)
}

func (s *alertScan) proposalFor(issue *scanner.Issue) *remediation.Proposal {
	for _, proposal := range s.engine.ListProposals() {
		if proposal.IssueID == issue.ID {
			return proposal
		}
	}
	return nil
}

func setPreAlertLimits(t *testing.T, limits preAlertOptions) {
	t.Helper()
	previous := preAlertLimits
	preAlertLimits = limits
	t.Cleanup(func() { preAlertLimits = previous })
}

// blockingProvider holds every diagnosis until release is closed, and notes
// whether one was cancelled instead.
func blockingProvider(release <-chan struct{}, cancelled *atomic.Bool) *scriptedProvider {
	return &scriptedProvider{diagnose: func(ctx context.Context, issue *scanner.Issue) (*triage.Diagnosis, error) {
		select {
		case <-release:
			return restartDiagnosis(issue), nil
		case <-ctx.Done():
			cancelled.Store(true)
			return nil, ctx.Err()
		}
	}}
}

func TestPreAlertTriageAnnotatesAlertsAndDiagnosesEachFindingOnce(t *testing.T) {
	crashing := crashLoopIssue("api-0")
	unrouted := &scanner.Issue{
		ID: "keycloak/Service/keycloak/NoEndpoints", Namespace: "keycloak", Kind: "Service", Name: "keycloak",
		Severity: scanner.SeverityHigh, Category: scanner.CategoryServiceNoEndpoint,
		Summary: "Service keycloak has no ready endpoints", Details: "Service selector matches 0 running, ready pods.",
	}
	posture := &scanner.Issue{
		ID: "ClusterRoleBinding/admin/Posture", Kind: "ClusterRoleBinding", Name: "admin",
		Severity: scanner.SeverityCritical, Category: scanner.CategorySecurityClusterBinding, Summary: "cluster-admin binding",
	}
	minor := &scanner.Issue{
		ID: "default/Pod/web-0/LogError", Namespace: "default", Kind: "Pod", Name: "web-0",
		Severity: scanner.SeverityMedium, Category: scanner.CategoryPodLogError, Summary: "old log error",
	}
	provider := &scriptedProvider{}
	scan := newAlertScan(t, &config.Config{}, provider, crashing, unrouted, posture, minor)

	alerts := scan.run(t)
	if len(alerts) != 2 {
		t.Fatalf("scan posted %d alerts, want the crash loop and the Service: %#v", len(alerts), alerts)
	}
	for _, issue := range []*scanner.Issue{crashing, unrouted} {
		alert := alerts[issue.Name]
		wantAction := "RestartPod: Restart " + issue.Name + " Proposed command: kubectl delete pod " + issue.Name + " -n " + issue.Namespace
		if alert.Annotations["analysis"] != "Root cause of "+issue.Name || alert.Annotations["recommended_action"] != wantAction || alert.Annotations["triage_provider"] != "scripted-provider" {
			t.Fatalf("alert for %s is not annotated with its diagnosis: %#v", issue.Name, alert.Annotations)
		}
		if !strings.HasPrefix(alert.Annotations["description"], "Analysis: Root cause of "+issue.Name+"\nRecommended action: "+wantAction+"\n"+issue.Details) {
			t.Fatalf("description for %s does not lead with the analysis: %q", issue.Name, alert.Annotations["description"])
		}
		if alert.Labels["severity"] != strings.ToLower(string(issue.Severity)) {
			t.Fatalf("alert for %s has severity %q", issue.Name, alert.Labels["severity"])
		}
	}

	// The proposal loop reuses what pre-alert triage diagnosed and diagnoses
	// the findings that do not alert itself: one diagnosis per finding.
	for _, issue := range []*scanner.Issue{crashing, unrouted, posture, minor} {
		if calls := provider.callsFor(issue); calls != 1 {
			t.Fatalf("%s was diagnosed %d times, want once", issue.ID, calls)
		}
	}
	proposal := scan.proposalFor(crashing)
	if proposal == nil || proposal.Diagnosis == nil || proposal.Diagnosis.RootCause != "Root cause of api-0" {
		t.Fatalf("no proposal was created from the pre-alert diagnosis: %#v", proposal)
	}
}

func TestPreAlertTriageDiagnosesAgainOnlyWhenEvidenceChanges(t *testing.T) {
	issue := crashLoopIssue("worker-0")
	issue.FirstObserved = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	issue.LastObserved = issue.FirstObserved
	provider := &scriptedProvider{}
	scan := newAlertScan(t, &config.Config{}, provider, issue)

	if alerts := scan.run(t); alerts["worker-0"].Annotations["analysis"] == "" {
		t.Fatalf("first scan sent an alert without analysis: %#v", alerts)
	}

	// The next scan observes the same failure later, on a newer
	// resourceVersion. There is nothing new to diagnose.
	later := *issue
	later.LastObserved = issue.LastObserved.Add(2 * time.Minute)
	later.TargetResourceVersion = "2"
	scan.service.report.Issues = []*scanner.Issue{&later}
	if alerts := scan.run(t); alerts["worker-0"].Annotations["analysis"] != "Root cause of worker-0" {
		t.Fatalf("second scan lost the analysis: %#v", alerts)
	}
	if calls := provider.totalCalls(); calls != 1 {
		t.Fatalf("an unchanged finding was diagnosed %d times, want once", calls)
	}

	changed := later
	changed.Details = "Container of worker-0 was OOMKilled"
	scan.service.report.Issues = []*scanner.Issue{&changed}
	scan.run(t)
	if calls := provider.totalCalls(); calls != 2 {
		t.Fatalf("a finding with new evidence was diagnosed %d times in total, want 2", calls)
	}
}

func TestPreAlertTriageSendsAlertWhenDiagnosisFails(t *testing.T) {
	const secret = "provider-error-secret-0123456789"
	issue := crashLoopIssue("db-0")
	issue.Details = "Container exited with code 137 token=" + secret
	provider := &scriptedProvider{diagnose: func(context.Context, *scanner.Issue) (*triage.Diagnosis, error) {
		return nil, errors.New("provider unavailable " + secret)
	}}
	scan := newAlertScan(t, &config.Config{APIToken: secret}, provider, issue)

	alert, sent := scan.run(t)["db-0"]
	if !sent {
		t.Fatal("a failed diagnosis kept the alert from being sent")
	}
	if _, annotated := alert.Annotations["analysis"]; annotated {
		t.Fatalf("alert carries an analysis although diagnosis failed: %#v", alert.Annotations)
	}
	if description := alert.Annotations["description"]; !strings.HasPrefix(description, "Container exited with code 137") || strings.Contains(description, secret) {
		t.Fatalf("description = %q, want the redacted scanner details", description)
	}
	// The failure is not retried within the scan, only by the next one.
	if calls := provider.callsFor(issue); calls != 1 {
		t.Fatalf("a failed diagnosis was asked for %d times in one scan, want once", calls)
	}
	if _, sent := scan.run(t)["db-0"]; !sent || provider.callsFor(issue) != 2 {
		t.Fatalf("next scan: alert sent = %t after %d diagnoses, want a resent alert and one retry", sent, provider.callsFor(issue))
	}
}

func TestPreAlertTriageDoesNotHoldAlertsForSlowProvider(t *testing.T) {
	for name, test := range map[string]struct {
		cfg          *config.Config
		wantProposal bool
	}{
		"proposal loop takes the late diagnosis": {cfg: &config.Config{}, wantProposal: true},
		// With playbooks on and no catalog, no proposal is made from a diagnosis.
		"scan keeps the late diagnosis without a proposal loop": {cfg: &config.Config{PlaybookEnabled: true}},
	} {
		t.Run(name, func(t *testing.T) {
			setPreAlertLimits(t, preAlertOptions{wait: 200 * time.Millisecond, concurrency: 2})
			release := make(chan struct{})
			var cancelled atomic.Bool
			provider := blockingProvider(release, &cancelled)
			issue := crashLoopIssue("slow-0")
			scan := newAlertScan(t, test.cfg, provider, issue)

			finished := make(chan error, 1)
			go func() { finished <- scan.scan() }()

			// The alert goes out while the provider is still thinking.
			alert, sent := scan.alerts.next(t)["slow-0"]
			if !sent {
				t.Fatal("a slow diagnosis kept the alert from being sent")
			}
			if _, annotated := alert.Annotations["analysis"]; annotated {
				t.Fatalf("alert carries an analysis that had not arrived: %#v", alert.Annotations)
			}
			select {
			case err := <-finished:
				t.Fatalf("scan returned (%v) while its diagnosis was still in flight", err)
			default:
			}

			close(release)
			if err := <-finished; err != nil {
				t.Fatalf("runSingleScan() error = %v", err)
			}
			if cancelled.Load() || provider.callsFor(issue) != 1 {
				t.Fatalf("the late diagnosis was cancelled (%t) or repeated (%d calls)", cancelled.Load(), provider.callsFor(issue))
			}
			if proposal := scan.proposalFor(issue); (proposal != nil) != test.wantProposal {
				t.Fatalf("proposal = %#v, want one: %t", proposal, test.wantProposal)
			}

			// The late diagnosis annotates the alert of the next scan for free.
			if next := scan.run(t)["slow-0"]; next.Annotations["analysis"] != "Root cause of slow-0" {
				t.Fatalf("next scan did not use the late diagnosis: %#v", next.Annotations)
			}
			if calls := provider.callsFor(issue); calls != 1 {
				t.Fatalf("finding was diagnosed %d times across both scans, want once", calls)
			}
		})
	}
}

func TestPreAlertTriageBoundsConcurrentDiagnoses(t *testing.T) {
	setPreAlertLimits(t, preAlertOptions{wait: 20 * time.Millisecond, concurrency: 2})
	release := make(chan struct{})
	var cancelled atomic.Bool
	provider := blockingProvider(release, &cancelled)
	issues := []*scanner.Issue{crashLoopIssue("p-1"), crashLoopIssue("p-2"), crashLoopIssue("p-3"), crashLoopIssue("p-4"), crashLoopIssue("p-5")}
	scan := newAlertScan(t, &config.Config{}, provider, issues...)

	finished := make(chan error, 1)
	go func() { finished <- scan.scan() }()

	// Every alert is sent although no diagnosis is in, and no more
	// diagnoses were started than may run at once.
	alerts := scan.alerts.next(t)
	if len(alerts) != len(issues) {
		t.Fatalf("scan posted %d alerts, want all %d", len(alerts), len(issues))
	}
	if started := provider.totalCalls(); started > 2 {
		t.Fatalf("%d diagnoses were started before dispatch, over the concurrency bound of 2", started)
	}

	close(release)
	if err := <-finished; err != nil {
		t.Fatalf("runSingleScan() error = %v", err)
	}
	if peak := provider.peakConcurrency(); peak > 2 || cancelled.Load() {
		t.Fatalf("peak concurrency = %d (bound 2), cancelled = %t", peak, cancelled.Load())
	}
	// The proposal loop diagnosed what pre-alert triage never started, so
	// each finding was still diagnosed exactly once.
	for _, issue := range issues {
		if calls := provider.callsFor(issue); calls != 1 {
			t.Fatalf("%s was diagnosed %d times, want once", issue.ID, calls)
		}
	}
	for name, alert := range scan.run(t) {
		if alert.Annotations["analysis"] != "Root cause of "+name {
			t.Fatalf("next scan sent %s without its analysis: %#v", name, alert.Annotations)
		}
	}
	if calls := provider.totalCalls(); calls != len(issues) {
		t.Fatalf("%d diagnoses across both scans, want %d", calls, len(issues))
	}
}

func TestAlertTriageStartsNoDiagnosisAfterTheWait(t *testing.T) {
	setPreAlertLimits(t, preAlertOptions{wait: 20 * time.Millisecond, concurrency: 2})
	alertmanager, err := notifier.NewAlertmanagerNotifier(notifier.AlertmanagerOptions{Endpoint: "http://alertmanager.invalid:9093"})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	release := make(chan struct{})
	var cancelled atomic.Bool
	provider := blockingProvider(release, &cancelled)
	issues := []*scanner.Issue{crashLoopIssue("p-1"), crashLoopIssue("p-2"), crashLoopIssue("p-3"), crashLoopIssue("p-4"), crashLoopIssue("p-5")}

	run := startAlertTriage(context.Background(), &config.Config{}, alertmanager, provider, issues)
	run.settle(context.Background())
	// The provider answers at once from here on. Workers that could still
	// take from the queue would now drain it.
	close(release)
	run.wait()

	taken := 0
	for _, issue := range issues {
		diagnosis, analyzed, err := run.result(context.Background(), issue)
		if !analyzed {
			continue
		}
		taken++
		if err != nil || diagnosis == nil {
			t.Fatalf("diagnosis of %s = %#v, %v", issue.ID, diagnosis, err)
		}
		if _, cached := alertmanager.CachedDiagnosis(issue); !cached {
			t.Fatalf("diagnosis of %s was not kept for the next scan", issue.ID)
		}
	}
	if taken > 2 || provider.totalCalls() != taken {
		t.Fatalf("%d diagnoses were taken on and %d asked of the provider, want at most the 2 started within the wait", taken, provider.totalCalls())
	}
}

func TestPreAlertTriageRedactsSecretsInAlerts(t *testing.T) {
	const databaseURL = "postgres://db_user:db-password@db.example.test:5432/sre?sslmode=require"
	leaks := []string{databaseURL, "db_user:db-password", "db-password"}
	issue := crashLoopIssue("payments-0")
	issue.Details = "connection to " + databaseURL + " refused"

	var seen *scanner.Issue
	provider := &scriptedProvider{diagnose: func(_ context.Context, issue *scanner.Issue) (*triage.Diagnosis, error) {
		seen = issue
		diagnosis := restartDiagnosis(issue)
		diagnosis.RootCause = "cannot reach " + databaseURL + " with db-password"
		diagnosis.RemediationPlan = "rotate db_user:db-password"
		return diagnosis, nil
	}}
	scan := newAlertScan(t, &config.Config{DatabaseURL: databaseURL}, provider, issue)

	alert := scan.run(t)["payments-0"]
	if alert.Annotations["analysis"] == "" || alert.Annotations["recommended_action"] == "" {
		t.Fatalf("alert is not annotated: %#v", alert.Annotations)
	}
	for _, leak := range leaks {
		if strings.Contains(seen.Details, leak) {
			t.Fatalf("provider was shown %q: %q", leak, seen.Details)
		}
		for annotation, value := range alert.Annotations {
			if strings.Contains(value, leak) {
				t.Fatalf("annotation %s leaked %q: %q", annotation, leak, value)
			}
		}
	}
}

func TestPreAlertTriageWithRuleEngineExplainsOrphanedService(t *testing.T) {
	issue := &scanner.Issue{
		ID: "keycloak/Service/keycloak/NoEndpoints", Namespace: "keycloak", Kind: "Service", Name: "keycloak",
		Severity: scanner.SeverityHigh, Category: scanner.CategoryServiceNoEndpoint,
		Summary: "Service keycloak has no ready endpoints",
		Details: "Service selector map[app:keycloak] matches 0 running, ready pods. Ingress impact: no Ingress in namespace keycloak targets keycloak. " +
			"Active sibling Service(s) with ready endpoints: keycloak-keycloak (1 ready) (" + scanner.ServiceLikelyOrphanedMarker + "; verify internal callers before cleanup).",
	}
	scan := newAlertScan(t, &config.Config{}, triage.NewRuleBasedProvider(), issue)

	annotations := scan.run(t)["keycloak"].Annotations
	if !strings.HasPrefix(annotations["analysis"], "No Ingress routes to this Service and a sibling Service is serving with ready endpoints, so this is most likely a leftover Service rather than an outage. Evidence: Service selector") {
		t.Fatalf("analysis = %q, want the orphaned-Service diagnosis", annotations["analysis"])
	}
	if !strings.HasPrefix(annotations["recommended_action"], "Manual: Confirm that no in-cluster client still calls this Service") ||
		!strings.HasSuffix(annotations["recommended_action"], "Proposed command: kubectl describe service keycloak -n keycloak") {
		t.Fatalf("recommended_action = %q", annotations["recommended_action"])
	}
	if annotations["triage_provider"] != "Rule-Based SRE Engine" {
		t.Fatalf("triage_provider = %q, want the rule engine", annotations["triage_provider"])
	}
}

func TestPreAlertTriageLeavesDisabledProviderAlone(t *testing.T) {
	alertmanager, err := notifier.NewAlertmanagerNotifier(notifier.AlertmanagerOptions{Endpoint: "http://alertmanager.invalid:9093"})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	issue := crashLoopIssue("api-0")

	run := startAlertTriage(context.Background(), &config.Config{}, alertmanager, triage.NewNoOpProvider(), []*scanner.Issue{issue})
	run.settle(context.Background())
	run.wait()
	if _, analyzed, _ := run.result(context.Background(), issue); analyzed || len(run.queue) != 0 {
		t.Fatalf("pre-alert triage asked a disabled provider for %d diagnoses", len(run.queue))
	}
}
