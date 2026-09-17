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

func TestDashboardShellAndModalContract(t *testing.T) {
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read embedded dashboard index: %v", err)
	}
	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read embedded dashboard app: %v", err)
	}
	indexText := string(index)
	appText := string(app)

	flexRule := strings.Index(indexText, ".flex {")
	modalHiddenRule := strings.Index(indexText, "#modal-backdrop.hidden")
	if flexRule < 0 {
		t.Fatal("dashboard styles are missing the generic .flex rule")
	}
	if modalHiddenRule < 0 || modalHiddenRule <= flexRule {
		t.Fatalf("dashboard modal needs a selector-specific #modal-backdrop.hidden rule after .flex so .flex cannot override .hidden")
	}
	if !regexp.MustCompile(`#modal-backdrop\.hidden\s*\{\s*display:\s*none\s*;?\s*\}`).MatchString(indexText[modalHiddenRule:]) {
		t.Fatal("#modal-backdrop.hidden must set display: none")
	}

	dialogText := dashboardDialogMarkup(t, indexText)
	for _, marker := range []string{
		`role="dialog"`,
		`aria-modal="true"`,
		`aria-labelledby="modal-title"`,
		`id="modal-title"`,
		`id="modal-content"`,
		`aria-label="Close Resource Logs"`,
		`<button type="button"`,
	} {
		if !strings.Contains(dialogText, marker) {
			t.Errorf("dashboard modal is missing %q", marker)
		}
	}

	for _, marker := range []string{
		`id="global-nav"`,
		`id="left-nav"`,
		`data-nav-group`,
		`id="cluster-context"`,
		`id="triage-queue"`,
		`id="issue-detail"`,
		`id="evidence-panel"`,
		`id="approval-panel"`,
		`id="metrics-panel"`,
		`id="settings-panel"`,
		`id="playbook-panel"`,
		`id="audit-panel"`,
		`id="stat-issues"`,
		`id="section-approvals"`,
		`id="tab-metrics"`,
		`id="section-metrics"`,
		`id="settings-provider"`,
	} {
		if !strings.Contains(indexText, marker) {
			t.Errorf("dashboard shell is missing approved marker %q", marker)
		}
	}
	for _, marker := range []string{`data-issue-row`, `data-issue-name`, `data-action="resource-logs"`} {
		if !strings.Contains(appText, marker) {
			t.Errorf("dashboard app is missing generated marker %q", marker)
		}
	}
}

func TestDashboardThemeContract(t *testing.T) {
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read embedded dashboard index: %v", err)
	}
	app, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read embedded dashboard app: %v", err)
	}

	indexText := string(index)
	appText := string(app)
	for _, marker := range []string{
		`<html lang="en" data-theme="system">`,
		`id="theme-select"`,
		`data-action="theme-change"`,
		`<option value="light">Light</option>`,
		`<option value="dark">Dark</option>`,
		`<option value="system">System</option>`,
		`@media (prefers-color-scheme: dark)`,
		`color-scheme: light`,
		`color-scheme: dark`,
	} {
		if !strings.Contains(indexText, marker) {
			t.Errorf("dashboard theme shell is missing %q", marker)
		}
	}
	for _, marker := range []string{
		`THEME_STORAGE_KEY`,
		`applyTheme`,
		`localStorage`,
		`theme-change`,
		`prefers-color-scheme`,
	} {
		if !strings.Contains(appText, marker) {
			t.Errorf("dashboard theme behavior is missing %q", marker)
		}
	}
}

func TestDashboardDoesNotExposeExternalAnalyzerBrand(t *testing.T) {
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read embedded dashboard index: %v", err)
	}
	if strings.Contains(strings.ToLower(string(index)), "k8sgpt") {
		t.Fatal("dashboard must not expose the external analyzer brand")
	}
}

func dashboardDialogMarkup(t *testing.T, indexText string) string {
	t.Helper()

	modalPattern := regexp.MustCompile(`(?is)<([A-Za-z][A-Za-z0-9:-]*)\b[^>]*\bid\s*=\s*["']modal-backdrop["'][^>]*>`)
	modalMatch := modalPattern.FindStringSubmatchIndex(indexText)
	if len(modalMatch) != 4 {
		t.Fatal("dashboard is missing #modal-backdrop")
	}
	modalStart := modalMatch[0]
	modalEnd := modalMatch[1]
	modalTagName := indexText[modalMatch[2]:modalMatch[3]]
	modalText := dashboardElementMarkup(t, indexText, modalStart, modalEnd, modalTagName)

	dialogPattern := regexp.MustCompile(`(?is)<([A-Za-z][A-Za-z0-9:-]*)\b[^>]*\brole\s*=\s*["']dialog["'][^>]*>`)
	match := dialogPattern.FindStringSubmatchIndex(modalText)
	if len(match) != 4 {
		t.Fatal("dashboard is missing a role=dialog element inside #modal-backdrop")
	}
	openStart := match[0]
	openEnd := match[1]
	tagName := modalText[match[2]:match[3]]
	return dashboardElementMarkup(t, modalText, openStart, openEnd, tagName)
}

func dashboardElementMarkup(t *testing.T, html string, openStart, openEnd int, tagName string) string {
	t.Helper()

	tagPattern := regexp.MustCompile(`(?is)</?` + regexp.QuoteMeta(tagName) + `(?:\s[^>]*?)?/?>`)
	depth := 1
	for cursor := openEnd; cursor < len(html); {
		tag := tagPattern.FindStringIndex(html[cursor:])
		if tag == nil {
			t.Fatalf("dashboard <%s> element is not closed", tagName)
		}
		tagStart := cursor + tag[0]
		tagEnd := cursor + tag[1]
		tagText := html[tagStart:tagEnd]
		if strings.HasPrefix(strings.TrimSpace(tagText), "</") {
			depth--
		} else if !strings.HasSuffix(strings.TrimSpace(tagText), "/>") {
			depth++
		}
		if depth == 0 {
			return html[openStart:tagEnd]
		}
		cursor = tagEnd
	}

	t.Fatalf("dashboard <%s> element is not closed", tagName)
	return ""
}
