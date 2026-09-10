package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/triage"
)

type WebhookNotifier struct {
	mu             sync.RWMutex
	webhookURL     string
	publicURL      string
	publicURLError error
	client         *http.Client
	redactor       *sanitizer.Redactor
	urlError       error
}

func NewWebhookNotifier(webhookURL, publicURL string, secretValues ...string) *WebhookNotifier {
	redactor := sanitizer.RedactorForSecrets(secretValues...)
	normalizedPublicURL, publicURLError := normalizePublicURL(publicURL)
	if normalizedPublicURL != "" {
		normalizedPublicURL = redactor.SanitizeURL(normalizedPublicURL)
	}
	notifier := &WebhookNotifier{
		publicURL:      normalizedPublicURL,
		publicURLError: publicURLError,
		client:         newWebhookHTTPClient(),
		redactor:       redactor,
	}
	if err := notifier.setWebhookURL(webhookURL); err != nil {
		// Preserve the configured value for redacted diagnostics while keeping
		// delivery fail-closed through destination().
		notifier.mu.Lock()
		notifier.webhookURL = strings.TrimSpace(webhookURL)
		notifier.urlError = err
		notifier.mu.Unlock()
	}
	return notifier
}

// SetWebhookURL updates the destination only after validating its scheme and
// address class. A non-nil error leaves the existing destination unchanged.
func (n *WebhookNotifier) SetWebhookURL(value string) error {
	if n == nil {
		return fmt.Errorf("webhook notifier is unavailable")
	}
	return n.setWebhookURL(value)
}

func (n *WebhookNotifier) setWebhookURL(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		if err := validateWebhookURL(value); err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.webhookURL = value
	n.urlError = nil
	n.mu.Unlock()
	return nil
}

func (n *WebhookNotifier) GetWebhookURL() string {
	if n == nil {
		return ""
	}
	n.mu.RLock()
	value := n.webhookURL
	n.mu.RUnlock()
	return n.redactorOrDefault().SanitizeURL(value)
}

// HasWebhookURL reports whether a destination is configured without exposing it.
func (n *WebhookNotifier) HasWebhookURL() bool {
	if n == nil {
		return false
	}
	n.mu.RLock()
	configured := n.webhookURL != ""
	n.mu.RUnlock()
	return configured
}

// NotifyProposalCreated formats and dispatches alert to Slack, Discord, MS Teams, or generic webhook
func (n *WebhookNotifier) NotifyProposalCreated(ctx context.Context, p *remediation.Proposal) error {
	url, configured, err := n.destination()
	if !configured {
		return nil
	}
	if err != nil {
		return err
	}
	if p == nil || p.Diagnosis == nil {
		return fmt.Errorf("proposal diagnosis is required")
	}
	return n.dispatchProposal(ctx, url, n.sanitizeProposal(p))
}

// NotifyExecutionResult dispatches notification when a proposal action completes or fails
func (n *WebhookNotifier) NotifyExecutionResult(ctx context.Context, p *remediation.Proposal) error {
	url, configured, err := n.destination()
	if !configured {
		return nil
	}
	if err != nil {
		return err
	}
	if p == nil || p.Diagnosis == nil {
		return fmt.Errorf("proposal diagnosis is required")
	}
	sanitized := n.sanitizeProposal(p)

	statusEmoji := "✅"
	statusText := "SUCCESS"
	color := 0x38A169 // Green
	if sanitized.Status == remediation.StatusFailed {
		statusEmoji = "❌"
		statusText = "FAILED"
		color = 0xE53E3E // Red
	}

	msgText := fmt.Sprintf("%s SRE Action Executed: %s on %s/%s [%s]\nResult: %s",
		statusEmoji, sanitized.Diagnosis.ActionType, sanitized.Kind, sanitized.Name, statusText, sanitized.ExecutionResult)
	if sanitized.ExecutionError != "" {
		msgText += fmt.Sprintf("\nError: %s", sanitized.ExecutionError)
	}

	return n.dispatchGeneric(ctx, url, msgText, color)
}

// SendTestNotification validates the webhook connection with a test message
func (n *WebhookNotifier) SendTestNotification(ctx context.Context, targetURL string) error {
	url := targetURL
	if url == "" {
		var err error
		url, _, err = n.destination()
		if err != nil {
			return err
		}
	}
	if url == "" {
		return fmt.Errorf("no webhook URL configured")
	}

	text := "🚀 **Kubebee SRE Agent**: Webhook notification integration test successful! Connected to cluster."
	return n.dispatchGeneric(ctx, url, text, 0x3182CE) // Blue
}

func (n *WebhookNotifier) dispatchProposal(ctx context.Context, url string, p *sanitizedProposal) error {
	approveLink, err := n.approvalURL(p.ID)
	if err != nil {
		return err
	}

	switch webhookProviderForURL(url) {
	case webhookProviderDiscord:
		return n.dispatchDiscordProposal(ctx, url, p, approveLink)
	case webhookProviderTeams:
		return n.dispatchTeamsProposal(ctx, url, p, approveLink)
	default:
		// Slack and generic webhooks use the Slack-compatible payload.
		return n.dispatchSlackProposal(ctx, url, p, approveLink)
	}
}

func (n *WebhookNotifier) dispatchSlackProposal(ctx context.Context, url string, p *sanitizedProposal, approveLink string) error {
	severityEmoji := "⚠️"
	color := "#DD6B20"
	if p.Diagnosis.Severity == "CRITICAL" {
		severityEmoji = "🚨"
		color = "#E53E3E"
	}

	headerText := fmt.Sprintf("%s [%s] SRE Remediation Required: %s/%s", severityEmoji, p.Diagnosis.Severity, p.Kind, p.Name)
	if p.Diagnosis.ActionType == triage.ActionBumpVersion || p.Diagnosis.ActionType == triage.ActionUpgradeApp {
		headerText = fmt.Sprintf("🛡️ %s [%s] SRE Security Fix / App Upgrade Approval Required: %s/%s", severityEmoji, p.Diagnosis.Severity, p.Kind, p.Name)
	}

	fields := []map[string]interface{}{
		{"title": "Namespace", "value": p.Namespace, "short": true},
		{"title": "Action Type", "value": string(p.Diagnosis.ActionType), "short": true},
	}
	if p.Diagnosis.TargetImage != "" {
		fields = append(fields, map[string]interface{}{"title": "Target Image", "value": fmt.Sprintf("`%s`", p.Diagnosis.TargetImage), "short": true})
	}
	if p.Diagnosis.TargetVersion != "" {
		fields = append(fields, map[string]interface{}{"title": "Target Version", "value": fmt.Sprintf("`%s`", p.Diagnosis.TargetVersion), "short": true})
	}
	fields = append(fields,
		map[string]interface{}{"title": "Proposed Command", "value": fmt.Sprintf("`%s`", p.Diagnosis.ProposedCommand), "short": false},
		map[string]interface{}{"title": "AI Confidence", "value": fmt.Sprintf("%.0f%% via %s", p.Diagnosis.ConfidenceScore*100, p.Diagnosis.ProviderName), "short": true},
		map[string]interface{}{"title": "Approve via Chat", "value": fmt.Sprintf("`/sre approve %s`", p.ID), "short": true},
		map[string]interface{}{"title": "Review & Authorize", "value": fmt.Sprintf("<%s|Open SRE Approval Console>", approveLink), "short": false},
	)

	payload := map[string]interface{}{
		"text": headerText,
		"attachments": []map[string]interface{}{
			{
				"color":  color,
				"title":  p.Diagnosis.Summary,
				"text":   p.Diagnosis.RootCause,
				"fields": fields,
			},
		},
	}

	return n.postJSON(ctx, url, payload)
}

func (n *WebhookNotifier) dispatchDiscordProposal(ctx context.Context, url string, p *sanitizedProposal, approveLink string) error {
	color := 0xDD6B20
	if p.Diagnosis.Severity == "CRITICAL" {
		color = 0xE53E3E
	}

	headerContent := fmt.Sprintf("🚨 **SRE Alert: %s/%s Requires Human Approval**", p.Kind, p.Name)
	if p.Diagnosis.ActionType == triage.ActionBumpVersion || p.Diagnosis.ActionType == triage.ActionUpgradeApp {
		headerContent = fmt.Sprintf("🛡️ **SRE Security Fix / App Upgrade Approval Required: %s/%s**", p.Kind, p.Name)
	}

	fields := []map[string]interface{}{
		{"name": "Namespace", "value": p.Namespace, "inline": true},
		{"name": "Severity", "value": string(p.Diagnosis.Severity), "inline": true},
		{"name": "Action", "value": string(p.Diagnosis.ActionType), "inline": true},
	}
	if p.Diagnosis.TargetImage != "" {
		fields = append(fields, map[string]interface{}{"name": "Target Image", "value": fmt.Sprintf("`%s`", p.Diagnosis.TargetImage), "inline": true})
	}
	if p.Diagnosis.TargetVersion != "" {
		fields = append(fields, map[string]interface{}{"name": "Target Version", "value": fmt.Sprintf("`%s`", p.Diagnosis.TargetVersion), "inline": true})
	}
	fields = append(fields,
		map[string]interface{}{"name": "Proposed Fix", "value": fmt.Sprintf("```bash\n%s\n```", p.Diagnosis.ProposedCommand), "inline": false},
		map[string]interface{}{"name": "Approve via Chat", "value": fmt.Sprintf("`/sre approve %s`", p.ID), "inline": true},
		map[string]interface{}{"name": "Approve / Reject Action", "value": fmt.Sprintf("[Click here to Review on Dashboard](%s)", approveLink), "inline": false},
	)

	payload := map[string]interface{}{
		"content": headerContent,
		"embeds": []map[string]interface{}{
			{
				"title":       p.Diagnosis.Summary,
				"description": p.Diagnosis.RootCause,
				"url":         approveLink,
				"color":       color,
				"fields":      fields,
				"footer": map[string]interface{}{
					"text": fmt.Sprintf("Kubebee SRE Agent • Diagnosed by %s", p.Diagnosis.ProviderName),
				},
			},
		},
	}

	return n.postJSON(ctx, url, payload)
}

func (n *WebhookNotifier) dispatchTeamsProposal(ctx context.Context, url string, p *sanitizedProposal, approveLink string) error {
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "E53E3E",
		"summary":    p.Diagnosis.Summary,
		"sections": []map[string]interface{}{
			{
				"activityTitle": fmt.Sprintf("🚨 SRE Approval Required: %s/%s", p.Kind, p.Name),
				"facts": []map[string]interface{}{
					{"name": "Namespace", "value": p.Namespace},
					{"name": "Severity", "value": string(p.Diagnosis.Severity)},
					{"name": "Action", "value": string(p.Diagnosis.ActionType)},
					{"name": "Diagnosis", "value": p.Diagnosis.RootCause},
					{"name": "Proposed Command", "value": p.Diagnosis.ProposedCommand},
				},
			},
		},
		"potentialAction": []map[string]interface{}{
			{
				"@type": "OpenUri",
				"name":  "Open SRE Approval Console",
				"targets": []map[string]interface{}{
					{"os": "default", "uri": approveLink},
				},
			},
		},
	}

	return n.postJSON(ctx, url, payload)
}

func (n *WebhookNotifier) dispatchGeneric(ctx context.Context, url string, message string, color int) error {
	switch webhookProviderForURL(url) {
	case webhookProviderDiscord:
		payload := map[string]interface{}{
			"embeds": []map[string]interface{}{
				{
					"description": message,
					"color":       color,
				},
			},
		}
		return n.postJSON(ctx, url, payload)
	case webhookProviderTeams:
		return n.dispatchTeamsGeneric(ctx, url, message, color)
	}

	// Slack and generic webhooks use the Slack-compatible payload.
	payload := map[string]interface{}{
		"text": message,
	}
	return n.postJSON(ctx, url, payload)
}

func (n *WebhookNotifier) dispatchTeamsGeneric(ctx context.Context, url string, message string, color int) error {
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": fmt.Sprintf("%06X", color&0xFFFFFF),
		"summary":    "Kubebee SRE Agent notification",
		"text":       message,
	}
	return n.postJSON(ctx, url, payload)
}

func (n *WebhookNotifier) postJSON(ctx context.Context, url string, data interface{}) error {
	redactor := n.redactorOrDefault()
	if err := validateWebhookURL(url); err != nil {
		return err
	}
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %s", redactor.SanitizeText(err.Error()))
	}
	body = []byte(redactor.SanitizeJSON(string(body)))
	if len(body) > maxWebhookPayloadBytes {
		return fmt.Errorf("webhook payload exceeds limit")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	client := n.client
	if client == nil {
		client = newWebhookHTTPClient()
	}

	// Webhooks are POSTs, so retries are deliberately limited to transient
	// failures and a small fixed attempt budget to bound duplicate delivery.
	for attempt := 1; attempt <= maxWebhookAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("dispatch webhook: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create webhook request: %s", redactor.SanitizeText(err.Error()))
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			if resp != nil && resp.Body != nil {
				_, _ = io.CopyN(io.Discard, resp.Body, maxWebhookResponseBytes+1)
				_ = resp.Body.Close()
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return fmt.Errorf("dispatch webhook: %w", ctxErr)
				}
				return fmt.Errorf("dispatch webhook: %s", redactor.SanitizeText(err.Error()))
			}
			if attempt < maxWebhookAttempts {
				if waitErr := waitWebhookRetry(ctx, webhookRetryDelay(attempt, "")); waitErr != nil {
					return fmt.Errorf("dispatch webhook: %w", waitErr)
				}
				continue
			}
			return fmt.Errorf("dispatch webhook: %s", redactor.SanitizeText(err.Error()))
		}

		statusCode := resp.StatusCode
		retryAfter := resp.Header.Get("Retry-After")
		if resp.Body != nil {
			_, _ = io.CopyN(io.Discard, resp.Body, maxWebhookResponseBytes+1)
			_ = resp.Body.Close()
		}
		if statusCode < http.StatusBadRequest {
			return nil
		}
		if attempt == maxWebhookAttempts || !retryableWebhookStatus(statusCode) {
			return fmt.Errorf("webhook responded with status %d", statusCode)
		}
		if err := waitWebhookRetry(ctx, webhookRetryDelay(attempt, retryAfter)); err != nil {
			return fmt.Errorf("dispatch webhook: %w", err)
		}
	}
	return fmt.Errorf("webhook delivery attempts exhausted")
}

const (
	maxWebhookPayloadBytes   = 128 * 1024
	maxWebhookResponseBytes  = 4 * 1024
	maxWebhookAttempts       = 3
	webhookRetryInitialDelay = 50 * time.Millisecond
	webhookRetryMaxDelay     = 500 * time.Millisecond
)

type webhookProvider string

const (
	webhookProviderGeneric = webhookProvider("generic")
	webhookProviderSlack   = webhookProvider("slack")
	webhookProviderDiscord = webhookProvider("discord")
	webhookProviderTeams   = webhookProvider("teams")
)

func webhookProviderForURL(raw string) webhookProvider {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil {
		return webhookProviderGeneric
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), "."))
	switch {
	case hostnameHasSuffix(host, "discord.com"), hostnameHasSuffix(host, "discordapp.com"):
		return webhookProviderDiscord
	case hostnameHasSuffix(host, "office.com"):
		return webhookProviderTeams
	case hostnameHasSuffix(host, "slack.com"):
		return webhookProviderSlack
	default:
		return webhookProviderGeneric
	}
}

func hostnameHasSuffix(host, suffix string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	suffix = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(suffix)), ".")
	return host != "" && suffix != "" && (host == suffix || strings.HasSuffix(host, "."+suffix))
}

func retryableWebhookStatus(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooEarly || statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

func webhookRetryDelay(attempt int, retryAfter string) time.Duration {
	delay := webhookRetryInitialDelay
	for index := 1; index < attempt && delay < webhookRetryMaxDelay; index++ {
		delay *= 2
	}
	if retryAfter != "" {
		if seconds, err := strconv.ParseInt(strings.TrimSpace(retryAfter), 10, 64); err == nil && seconds >= 0 {
			if seconds == 0 {
				delay = 0
			} else if webhookRetryMaxDelay < time.Second || seconds > int64(webhookRetryMaxDelay/time.Second) {
				delay = webhookRetryMaxDelay
			} else {
				delay = time.Duration(seconds) * time.Second
			}
		} else if retryAt, err := http.ParseTime(retryAfter); err == nil {
			if until := time.Until(retryAt); until > delay {
				delay = until
			}
		}
	}
	if delay > webhookRetryMaxDelay {
		return webhookRetryMaxDelay
	}
	return delay
}

func waitWebhookRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *WebhookNotifier) destination() (string, bool, error) {
	if n == nil {
		return "", false, fmt.Errorf("webhook notifier is unavailable")
	}
	n.mu.RLock()
	url := n.webhookURL
	err := n.urlError
	n.mu.RUnlock()
	return url, url != "", err
}

func validateWebhookURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.Hostname() == "" || parsed.User != nil || strings.ContainsAny(raw, "\r\n\x00") {
		return fmt.Errorf("webhook URL is not allowed")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return fmt.Errorf("webhook URL is not allowed")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if parsed.Scheme == "http" && !isLocalWebhookHost(host) {
		return fmt.Errorf("webhook URL is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil && !allowedWebhookIP(ip) {
		return fmt.Errorf("webhook URL is not allowed")
	}
	return nil
}

func normalizePublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.ContainsAny(raw, "\r\n\x00") {
		return "", fmt.Errorf("public approval URL is not allowed")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" {
		return "", fmt.Errorf("public approval URL is not allowed")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("public approval URL is not allowed")
	}
	if parsed.Scheme == "http" && !isLocalWebhookHost(parsed.Hostname()) {
		return "", fmt.Errorf("public approval URL is not allowed")
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String(), nil
}

func (n *WebhookNotifier) approvalURL(proposalID string) (string, error) {
	if n == nil {
		return "", fmt.Errorf("webhook notifier is unavailable")
	}
	if n.publicURLError != nil {
		return "", fmt.Errorf("public approval URL is not allowed")
	}
	fragment := approvalFragment(n.redactorOrDefault(), proposalID)
	if n.publicURL == "" {
		return "/#" + fragment, nil
	}
	parsed, err := url.Parse(n.publicURL)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("public approval URL is not allowed")
	}
	parsed.Fragment = fragment
	parsed.RawFragment = ""
	return n.redactorOrDefault().SanitizeURL(parsed.String()), nil
}

func approvalFragment(redactor *sanitizer.Redactor, proposalID string) string {
	proposalID = strings.TrimSpace(redactor.SanitizeText(proposalID))
	var sanitized strings.Builder
	for _, character := range proposalID {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			sanitized.WriteRune(character)
			continue
		}
		if sanitized.Len() == 0 || !strings.HasSuffix(sanitized.String(), "-") {
			sanitized.WriteByte('-')
		}
	}
	value := strings.Trim(sanitized.String(), "-")
	if value == "" {
		value = "proposal"
	}
	if len(value) > 128 {
		value = value[:128]
	}
	return "proposal-" + value
}

func isLocalWebhookHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func allowedWebhookIP(ip net.IP) bool {
	return ip != nil && (ip.IsLoopback() || (!ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && !ip.IsMulticast()))
}

func newWebhookHTTPClient() *http.Client {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Client{Timeout: 10 * time.Second}
	}
	transport = transport.Clone()
	transport.Proxy = nil
	transport.DialContext = safeWebhookDialContext
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}
}

func safeWebhookDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("webhook destination unavailable")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("webhook destination unavailable")
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	for _, candidate := range addresses {
		if !allowedWebhookIP(candidate.IP) {
			continue
		}
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if dialErr == nil {
			return connection, nil
		}
	}
	return nil, fmt.Errorf("webhook destination unavailable")
}

type sanitizedProposal struct {
	ID              string
	Namespace       string
	Kind            string
	Name            string
	Diagnosis       *triage.SanitizedDiagnosis
	Status          remediation.ProposalStatus
	ExecutionResult string
	ExecutionError  string
}

func (n *WebhookNotifier) redactorOrDefault() *sanitizer.Redactor {
	if n != nil && n.redactor != nil {
		return n.redactor
	}
	return sanitizer.DefaultRedactor()
}

func (n *WebhookNotifier) sanitizeProposal(p *remediation.Proposal) *sanitizedProposal {
	redactor := n.redactorOrDefault()
	result := &sanitizedProposal{
		ID:              redactor.SanitizeText(p.ID),
		Namespace:       redactor.SanitizeText(p.Namespace),
		Kind:            redactor.SanitizeText(p.Kind),
		Name:            redactor.SanitizeText(p.Name),
		Status:          p.Status,
		ExecutionResult: redactor.SanitizeText(p.ExecutionResult),
		ExecutionError:  redactor.SanitizeText(p.ExecutionError),
	}
	if p.Diagnosis != nil {
		result.Diagnosis = p.Diagnosis.SanitizedWithRedactor(redactor)
	}
	return result
}
