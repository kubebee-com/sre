package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

const (
	defaultAlertmanagerTTL        = 15 * time.Minute
	maxAlertmanagerLabelBytes     = 256
	maxAlertmanagerSummaryBytes   = 512
	maxAlertmanagerDescBytes      = 4096
	maxAlertmanagerBatchAlerts    = 250
	defaultAlertmanagerTimeout    = 10 * time.Second
	defaultAlertmanagerMinSev     = scanner.SeverityHigh
	defaultAlertmanagerClusterKey = "default"
)

// AlertmanagerOptions configures Alertmanager v2 API delivery for folded
// serious SRE findings.
type AlertmanagerOptions struct {
	Endpoint       string
	MinSeverity    string
	IncludePosture bool
	PublicURL      string
	ClusterName    string
	SecretValues   []string
}

type alertmanagerAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// AlertmanagerNotifier posts deduplicated, folded serious findings to an
// Alertmanager /api/v2/alerts endpoint and marks cleared findings as resolved.
type AlertmanagerNotifier struct {
	mu             sync.Mutex
	endpoint       string
	minSeverity    scanner.Severity
	includePosture bool
	publicURL      string
	clusterName    string
	redactor       *sanitizer.Redactor
	client         *http.Client
	active         map[string]alertmanagerAlert
	now            func() time.Time
}

// NewAlertmanagerNotifier builds a failsafe Alertmanager v2 alerts client.
func NewAlertmanagerNotifier(options AlertmanagerOptions) (*AlertmanagerNotifier, error) {
	redactor := sanitizer.RedactorForSecrets(options.SecretValues...)
	endpoint, err := normalizeAlertmanagerEndpoint(options.Endpoint)
	if err != nil {
		return nil, err
	}
	minSeverity, err := ParseAlertmanagerMinSeverity(options.MinSeverity)
	if err != nil {
		return nil, err
	}
	publicURL, _ := normalizePublicURL(options.PublicURL)
	if publicURL != "" {
		publicURL = redactor.SanitizeURL(publicURL)
	}
	clusterName := strings.TrimSpace(redactor.SanitizeText(options.ClusterName))
	if clusterName == "" {
		clusterName = defaultAlertmanagerClusterKey
	}
	return &AlertmanagerNotifier{
		endpoint:       endpoint,
		minSeverity:    minSeverity,
		includePosture: options.IncludePosture,
		publicURL:      publicURL,
		clusterName:    boundLabelValue(clusterName),
		redactor:       redactor,
		client: &http.Client{
			Timeout:   defaultAlertmanagerTimeout,
			Transport: cloneDirectTransport(),
		},
		active: make(map[string]alertmanagerAlert),
		now:    func() time.Time { return time.Now().UTC() },
	}, nil
}

func cloneDirectTransport() *http.Transport {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || transport == nil {
		return &http.Transport{}
	}
	cloned := transport.Clone()
	cloned.Proxy = nil
	return cloned
}

// Enabled reports whether a valid Alertmanager endpoint is configured.
func (n *AlertmanagerNotifier) Enabled() bool {
	return n != nil && n.endpoint != ""
}

// ParseAlertmanagerMinSeverity parses CRITICAL/HIGH/MEDIUM/LOW (default HIGH).
func ParseAlertmanagerMinSeverity(raw string) (scanner.Severity, error) {
	trimmed := strings.ToUpper(strings.TrimSpace(raw))
	if trimmed == "" {
		return defaultAlertmanagerMinSev, nil
	}
	sev := scanner.Severity(trimmed)
	if scanner.SeverityRank(sev) == 0 {
		return "", fmt.Errorf("invalid alertmanager min severity %q", raw)
	}
	return sev, nil
}

func normalizeAlertmanagerEndpoint(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", fmt.Errorf("alertmanager URL contains invalid control characters")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed == nil || parsed.Hostname() == "" || parsed.User != nil {
		return "", fmt.Errorf("alertmanager URL is invalid")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("alertmanager URL scheme must be http or https")
	}
	cleanPath := strings.TrimRight(parsed.Path, "/")
	if !strings.HasSuffix(cleanPath, "/api/v2/alerts") {
		parsed.Path = cleanPath + "/api/v2/alerts"
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String(), nil
}

// IsAlertableIssue determines whether a folded finding qualifies for Alertmanager
// escalation based on severity and passive-posture filtering.
func (n *AlertmanagerNotifier) IsAlertableIssue(issue *scanner.Issue) bool {
	if issue == nil {
		return false
	}
	minSeverity := defaultAlertmanagerMinSev
	includePosture := false
	if n != nil {
		minSeverity = n.minSeverity
		includePosture = n.includePosture
	}
	if scanner.SeverityRank(issue.Severity) < scanner.SeverityRank(minSeverity) {
		return false
	}
	if !includePosture && isPassivePostureCategory(issue.Category) {
		return false
	}
	return true
}

func isPassivePostureCategory(category scanner.IssueCategory) bool {
	switch category {
	case scanner.CategorySecurityPrivilege,
		scanner.CategorySecurityClusterBinding,
		scanner.CategoryPodVulnerability,
		scanner.CategoryClusterSecurityRisk,
		scanner.CategoryAppUpdateAvailable,
		scanner.CategoryConfigMapUnused,
		scanner.CategoryConfigMapEmpty:
		return true
	default:
		return false
	}
}

// eligibleIssues returns the folded findings that qualify for Alertmanager
// escalation, in input order and with one finding per alert key.
func (n *AlertmanagerNotifier) eligibleIssues(folded []*scanner.Issue) []*scanner.Issue {
	eligible := make([]*scanner.Issue, 0, len(folded))
	seen := make(map[string]struct{}, len(folded))
	for _, item := range folded {
		if !n.IsAlertableIssue(item) {
			continue
		}
		key := n.alertKey(item)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		eligible = append(eligible, item)
	}
	return eligible
}

// alertKey is the stable identity of a finding's alert: its fold_key label.
func (n *AlertmanagerNotifier) alertKey(issue *scanner.Issue) string {
	key := strings.TrimSpace(issue.FoldKey)
	if key == "" {
		key = issue.ID
	}
	if key == "" {
		key = fmt.Sprintf("%s-%s-%s-%s", issue.Namespace, issue.Kind, issue.Name, issue.Category)
	}
	return boundLabelValue(n.redactorOrDefault().SanitizeText(key))
}

func (n *AlertmanagerNotifier) redactorOrDefault() *sanitizer.Redactor {
	if n != nil && n.redactor != nil {
		return n.redactor
	}
	return sanitizer.DefaultRedactor()
}

// SyncFoldedIssues sends firing alerts for serious folded findings and, when
// fullScope is true, emits explicit resolved transitions for cleared alerts.
// diagnoses holds, by folded finding, the diagnoses that are available: a
// finding in it is annotated with its analysis, and any other finding is sent
// as the scanner found it. It may be nil.
func (n *AlertmanagerNotifier) SyncFoldedIssues(ctx context.Context, folded []*scanner.Issue, diagnoses map[*scanner.Issue]*triage.Diagnosis, fullScope bool) error {
	if !n.Enabled() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	now := n.now().UTC()
	eligible := n.eligibleIssues(folded)
	desired := make(map[string]alertmanagerAlert, len(eligible))
	desiredOrder := make([]string, 0, len(eligible))

	for _, item := range eligible {
		alert := n.buildAlert(item, diagnoses[item], now)
		key := alert.Labels["fold_key"]
		desired[key] = alert
		desiredOrder = append(desiredOrder, key)
	}

	sort.Strings(desiredOrder)

	n.mu.Lock()
	batch := make([]alertmanagerAlert, 0, len(desiredOrder)+len(n.active))
	for _, key := range desiredOrder {
		alert := desired[key]
		if existing, ok := n.active[key]; ok && !existing.StartsAt.IsZero() {
			alert.StartsAt = existing.StartsAt
		}
		n.active[key] = alert
		if len(batch) < maxAlertmanagerBatchAlerts {
			batch = append(batch, alert)
		}
	}
	if fullScope {
		resolvedKeys := make([]string, 0)
		for key := range n.active {
			if _, stillActive := desired[key]; !stillActive {
				resolvedKeys = append(resolvedKeys, key)
			}
		}
		sort.Strings(resolvedKeys)
		for _, key := range resolvedKeys {
			resolved := n.active[key]
			resolved.EndsAt = now
			if len(batch) < maxAlertmanagerBatchAlerts {
				batch = append(batch, resolved)
			}
			delete(n.active, key)
		}
	}
	n.mu.Unlock()

	if len(batch) == 0 {
		return nil
	}
	return n.postAlerts(ctx, batch)
}

func (n *AlertmanagerNotifier) buildAlert(issue *scanner.Issue, diagnosis *triage.Diagnosis, now time.Time) alertmanagerAlert {
	redactor := n.redactorOrDefault()
	ns := strings.TrimSpace(issue.Namespace)
	if ns == "" {
		ns = "cluster"
	}
	group := issue.Group
	if group == "" {
		group = scanner.ResolveFindingGroup(issue.Category)
	}
	resourceKind := issue.Kind
	resourceName := issue.Name
	if issue.Parent != nil && strings.TrimSpace(issue.Parent.Name) != "" {
		if strings.TrimSpace(issue.Parent.Kind) != "" {
			resourceKind = issue.Parent.Kind
		}
		resourceName = issue.Parent.Name
	}
	occurrences := issue.OccurrenceCount
	if occurrences < 1 {
		occurrences = 1
	}

	startsAt := now
	if !issue.FirstObserved.IsZero() && issue.FirstObserved.Before(now) {
		startsAt = issue.FirstObserved.UTC()
	}

	summary := redactor.SanitizeText(issue.Summary)
	if occurrences > 1 && !strings.Contains(summary, strconv.Itoa(occurrences)) {
		summary = fmt.Sprintf("%s (%d occurrences)", summary, occurrences)
	}
	summary = truncateUTF8(summary, maxAlertmanagerSummaryBytes)

	analysis := alertAnalysis(redactor, issue, diagnosis)
	recommendedAction := alertRecommendedAction(redactor, diagnosis)

	labels := map[string]string{
		"alertname":     boundLabelValue("KubebeeSRE" + sanitizeAlertNameToken(string(issue.Category))),
		"component":     "kubebee-sre",
		"severity":      boundLabelValue(strings.ToLower(string(issue.Severity))),
		"category":      boundLabelValue(string(issue.Category)),
		"finding_group": boundLabelValue(string(group)),
		"namespace":     boundLabelValue(redactor.SanitizeText(ns)),
		"resource_kind": boundLabelValue(redactor.SanitizeText(resourceKind)),
		"resource_name": boundLabelValue(redactor.SanitizeText(resourceName)),
		"fold_key":      n.alertKey(issue),
		"cluster":       n.clusterName,
	}

	// Analysis only ever adds annotations. Labels, and so the identity,
	// severity, and routing of the alert, come from the scanner alone.
	annotations := map[string]string{
		"summary":          summary,
		"description":      alertDescription(redactor, issue, analysis, recommendedAction),
		"occurrence_count": strconv.Itoa(occurrences),
	}
	if analysis != "" {
		annotations["analysis"] = analysis
	}
	if recommendedAction != "" {
		annotations["recommended_action"] = recommendedAction
	}
	if diagnosis != nil {
		if provider := boundLabelValue(redactor.SanitizeText(diagnosis.ProviderName)); provider != "" {
			annotations["triage_provider"] = provider
		}
	}
	if n.publicURL != "" {
		annotations["dashboard_url"] = n.publicURL
	}

	return alertmanagerAlert{
		Labels:       labels,
		Annotations:  annotations,
		StartsAt:     startsAt,
		EndsAt:       now.Add(defaultAlertmanagerTTL),
		GeneratorURL: n.publicURL,
	}
}

func (n *AlertmanagerNotifier) postAlerts(ctx context.Context, alerts []alertmanagerAlert) error {
	body, err := json.Marshal(alerts)
	if err != nil {
		return fmt.Errorf("encode alertmanager alerts: %w", err)
	}
	redactor := n.redactorOrDefault()
	var lastErr error
	for attempt := 0; attempt < maxWebhookAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build alertmanager request: %s", redactor.SanitizeText(err.Error()))
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := n.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("alertmanager delivery error: %s", redactor.SanitizeText(err.Error()))
			if attempt+1 < maxWebhookAttempts {
				if waitErr := waitWebhookRetry(ctx, webhookRetryDelay(attempt+1, "")); waitErr != nil {
					return waitErr
				}
				continue
			}
			return lastErr
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxWebhookResponseBytes+1))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("alertmanager returned status %d", resp.StatusCode)
		if !retryableWebhookStatus(resp.StatusCode) || attempt+1 >= maxWebhookAttempts {
			return lastErr
		}
		if waitErr := waitWebhookRetry(ctx, webhookRetryDelay(attempt+1, resp.Header.Get("Retry-After"))); waitErr != nil {
			return waitErr
		}
	}
	return lastErr
}

func sanitizeAlertNameToken(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "Issue"
	}
	return b.String()
}

func boundLabelValue(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\n", " "), "\r", " "))
	return truncateUTF8(value, maxAlertmanagerLabelBytes)
}

// truncateUTF8 bounds value to maxBytes without splitting a multi-byte rune.
func truncateUTF8(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for len(value) > 0 {
		if r, size := utf8.DecodeLastRuneInString(value); r != utf8.RuneError || size != 1 {
			break
		}
		value = value[:len(value)-1]
	}
	return value
}
