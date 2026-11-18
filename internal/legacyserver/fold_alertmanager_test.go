package legacyserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/metrics"
	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

func TestFoldedIssuesCategoriesStatusAndMetrics(t *testing.T) {
	reg := metrics.NewRegistry()
	am, err := notifier.NewAlertmanagerNotifier(notifier.AlertmanagerOptions{
		Endpoint: "http://monitoring-alertmanager.monitoring.svc.cluster.local:9093",
	})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	s := NewServer(0, nil, triage.NewRuleBasedProvider(), nil, nil, ServerOptions{
		Metrics:      reg,
		Alertmanager: am,
		Runtime: RuntimeSettings{
			AlertmanagerConfigured: true,
		},
	})
	s.SetActiveIssues([]*scanner.Issue{
		{
			ID: "apps/Pod/job-1/LogError", Namespace: "apps", Kind: "Pod", Name: "job-1",
			Severity: scanner.SeverityHigh, Category: scanner.CategoryPodLogError,
			Summary: "Pod job-1 has current error patterns in regular container logs",
			Parent:  &scanner.ResourceRef{Namespace: "apps", Kind: "Job", Name: "job"},
		},
		{
			ID: "apps/Pod/job-2/LogError", Namespace: "apps", Kind: "Pod", Name: "job-2",
			Severity: scanner.SeverityHigh, Category: scanner.CategoryPodLogError,
			Summary: "Pod job-2 has current error patterns in regular container logs",
			Parent:  &scanner.ResourceRef{Namespace: "apps", Kind: "Job", Name: "job"},
		},
		{
			ID: "ingress-nginx/Service/ingress/HC", Namespace: "ingress-nginx", Kind: "Service", Name: "ingress",
			Severity: scanner.SeverityCritical, Category: scanner.CategoryServiceHealthCheck,
			Summary: "Service ingress healthCheckNodePort 31543 is disabled by Cilium CNI config",
		},
	})
	h := testHandler(t, s)

	// Default /api/issues folds the two Job pods into 1 -> 2 total folded issues.
	foldedResp := serveTestRequest(h, http.MethodGet, "/api/issues", "", "")
	if foldedResp.Code != http.StatusOK {
		t.Fatalf("GET /api/issues status = %d: %s", foldedResp.Code, foldedResp.Body.String())
	}
	var folded []scanner.SanitizedIssue
	if err := json.Unmarshal(foldedResp.Body.Bytes(), &folded); err != nil {
		t.Fatalf("decode folded issues: %v", err)
	}
	if len(folded) != 2 {
		t.Fatalf("GET /api/issues returned %d folded issues, want 2: %#v", len(folded), folded)
	}

	// ?folded=false returns all 3 raw issues.
	rawResp := serveTestRequest(h, http.MethodGet, "/api/issues?folded=false", "", "")
	var raw []scanner.SanitizedIssue
	if err := json.Unmarshal(rawResp.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw issues: %v", err)
	}
	if len(raw) != 3 {
		t.Fatalf("GET /api/issues?folded=false returned %d issues, want 3", len(raw))
	}

	// /api/issues/categories summarizes all categories.
	catResp := serveTestRequest(h, http.MethodGet, "/api/issues/categories", "", "")
	if catResp.Code != http.StatusOK {
		t.Fatalf("GET /api/issues/categories status = %d", catResp.Code)
	}
	var cats []scanner.CategorySummary
	if err := json.Unmarshal(catResp.Body.Bytes(), &cats); err != nil {
		t.Fatalf("decode categories: %v", err)
	}
	if len(cats) != 2 {
		t.Fatalf("categories count = %d, want 2: %#v", len(cats), cats)
	}

	// /api/status matches folded count and reports alertmanager_configured.
	statusResp := serveTestRequest(h, http.MethodGet, "/api/status", "", "")
	var status StatusResponse
	if err := json.Unmarshal(statusResp.Body.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.ActiveIssuesCount != 2 || status.RawActiveIssuesCount != 3 || status.FoldedCategoriesCount != 2 || !status.Settings.AlertmanagerConfigured {
		t.Fatalf("unexpected StatusResponse = %#v", status)
	}

	// /metrics exports folded & active issue gauges.
	metricsResp := serveTestRequest(h, http.MethodGet, "/metrics", "", "")
	body := metricsResp.Body.String()
	for _, want := range []string{`sre_active_issues{`, `sre_folded_issues{`, `ServiceHealthCheckUnreachable`} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q:\n%s", want, body)
		}
	}
}
