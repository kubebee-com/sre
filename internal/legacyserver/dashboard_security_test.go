package legacyserver

import (
	"encoding/json"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestDashboardIssuePayloadCannotBecomeInlineJavaScript(t *testing.T) {
	fixture, err := staticFS.ReadFile("static/testdata/malicious-issue.json")
	if err != nil {
		t.Fatalf("read malicious issue fixture: %v", err)
	}
	var issue struct {
		Details     string `json:"details"`
		LogsSnippet string `json:"logs_snippet"`
		Name        string `json:"name"`
	}
	if err := json.Unmarshal(fixture, &issue); err != nil {
		t.Fatalf("parse malicious issue fixture: %v", err)
	}
	if !strings.Contains(issue.LogsSnippet, "<script>") || !strings.Contains(issue.Details, "window.location") {
		t.Fatal("malicious issue fixture does not contain the expected script payload")
	}

	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read embedded dashboard app: %v", err)
	}
	appText := string(app)
	inlineHandler := regexp.MustCompile(`(?i)\bon[a-z]+\s*=`)
	if handler := inlineHandler.FindString(appText); handler != "" {
		t.Fatalf("dashboard app emits inline event handler %q", handler)
	}
	for _, marker := range []string{
		"showLogsModal('${",
		"askAIAboutIssue('${",
		"cleanSinglePod('${",
		"approveProposal('${",
		"rejectProposal('${",
	} {
		if strings.Contains(appText, marker) {
			t.Errorf("dashboard app interpolates untrusted data into inline JavaScript marker %q", marker)
		}
	}
}

func TestDashboardLocalStylesCoverUsedUtilityClasses(t *testing.T) {
	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read embedded dashboard app: %v", err)
	}
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read embedded dashboard index: %v", err)
	}

	appText := string(app)
	indexText := string(index)
	for _, class := range []string{"bg-gray-800", "bg-red-500/20", "text-red-400"} {
		if !strings.Contains(appText, class) {
			t.Fatalf("dashboard app no longer uses utility class %q", class)
		}
		if !strings.Contains(indexText, `[class~="`+class+`"]`) {
			t.Errorf("local dashboard styles do not define utility class %q", class)
		}
	}
	if !strings.Contains(indexText, "max-h-[80vh]") {
		t.Fatal("dashboard modal no longer uses max-h-[80vh]")
	}
	if !strings.Contains(indexText, `[class~="max-h-[80vh]"]`) {
		t.Error("local dashboard styles do not define utility class max-h-[80vh]")
	}
	if !strings.Contains(indexText, ".pt-2") {
		t.Error("local dashboard styles do not define utility class pt-2")
	}
	for _, class := range []string{"text-[#5059C9]", "text-[#5865F2]", "text-[#E01E5A]"} {
		if !strings.Contains(indexText, `[class~="`+class+`"]`) {
			t.Errorf("local dashboard styles do not define arbitrary color utility %q", class)
		}
	}
}

func TestDashboardIncludesMetricsAndSafeSettingsSurface(t *testing.T) {
	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read embedded dashboard app: %v", err)
	}
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read embedded dashboard index: %v", err)
	}

	appText := string(app)
	indexText := string(index)
	for _, marker := range []string{
		"tab-metrics",
		"section-metrics",
		"metric-error-count",
		"metric-token-total",
		"settings-provider",
		"settings-wire-api",
		"settings-model",
		"settings-scan-interval",
		"settings-event-driven",
		"settings-event-queue-capacity",
		"settings-event-debounce",
		"settings-cache",
	} {
		if !strings.Contains(indexText, marker) {
			t.Errorf("dashboard index is missing %q", marker)
		}
	}
	for _, marker := range []string{
		"loadDashboardMetrics",
		"parsePrometheusMetrics",
		"/metrics",
		"sre_provider_tokens_total",
		"sre_errors_total",
		"escapeHtml",
	} {
		if !strings.Contains(appText, marker) {
			t.Errorf("dashboard app is missing %q", marker)
		}
	}
}

func TestDashboardIncludesPlaybookReviewAndUsage(t *testing.T) {
	index, _ := staticFS.ReadFile("static/index.html")
	app, _ := staticFS.ReadFile("static/app.js")
	for _, marker := range []string{"tab-playbooks", "section-playbooks", "playbook-import-form", "playbook-settings-form", "playbook-catalog", "playbook-task-usage", "playbook-outcomes"} {
		if !strings.Contains(string(index), marker) {
			t.Errorf("missing dashboard surface %s", marker)
		}
	}
	for _, marker := range []string{"loadPlaybooks", "renderPlaybookCatalog", "/api/v1/playbooks", "token_usage", "Unavailable", "playbook-transition"} {
		if !strings.Contains(string(app), marker) {
			t.Errorf("missing dashboard behavior %s", marker)
		}
	}
}

func TestDashboardPlaybookContentRemainsText(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is unavailable")
	}
	output, err := exec.Command(node, "static/testdata/playbook-dashboard-security.js").CombinedOutput()
	if err != nil {
		t.Fatalf("dashboard DOM security check: %v\n%s", err, output)
	}
}
