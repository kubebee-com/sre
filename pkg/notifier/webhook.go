package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/remediation"
)

type WebhookNotifier struct {
	webhookURL string
	publicURL  string
	client     *http.Client
}

func NewWebhookNotifier(webhookURL, publicURL string) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		publicURL:  publicURL,
		client:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *WebhookNotifier) SetWebhookURL(url string) {
	n.webhookURL = url
}

func (n *WebhookNotifier) GetWebhookURL() string {
	return n.webhookURL
}

// NotifyProposalCreated formats and dispatches alert to Slack, Discord, MS Teams, or generic webhook
func (n *WebhookNotifier) NotifyProposalCreated(ctx context.Context, p *remediation.Proposal) error {
	if n.webhookURL == "" {
		return nil
	}
	return n.dispatchProposal(ctx, n.webhookURL, p)
}

// NotifyExecutionResult dispatches notification when a proposal action completes or fails
func (n *WebhookNotifier) NotifyExecutionResult(ctx context.Context, p *remediation.Proposal) error {
	if n.webhookURL == "" {
		return nil
	}

	statusEmoji := "✅"
	statusText := "SUCCESS"
	color := 0x38A169 // Green
	if p.Status == remediation.StatusFailed {
		statusEmoji = "❌"
		statusText = "FAILED"
		color = 0xE53E3E // Red
	}

	msgText := fmt.Sprintf("%s SRE Action Executed: %s on %s/%s [%s]\nResult: %s",
		statusEmoji, p.Diagnosis.ActionType, p.Kind, p.Name, statusText, p.ExecutionResult)
	if p.ExecutionError != "" {
		msgText += fmt.Sprintf("\nError: %s", p.ExecutionError)
	}

	return n.dispatchGeneric(ctx, n.webhookURL, msgText, color)
}

// SendTestNotification validates the webhook connection with a test message
func (n *WebhookNotifier) SendTestNotification(ctx context.Context, targetURL string) error {
	url := targetURL
	if url == "" {
		url = n.webhookURL
	}
	if url == "" {
		return fmt.Errorf("no webhook URL configured")
	}

	text := "🚀 **Kubebee SRE Agent**: Webhook notification integration test successful! Connected to cluster."
	return n.dispatchGeneric(ctx, url, text, 0x3182CE) // Blue
}

func (n *WebhookNotifier) dispatchProposal(ctx context.Context, url string, p *remediation.Proposal) error {
	approveLink := fmt.Sprintf("%s/#proposal-%s", n.publicURL, p.ID)

	if strings.Contains(url, "discord.com") {
		return n.dispatchDiscordProposal(ctx, url, p, approveLink)
	}
	if strings.Contains(url, "office.com") {
		return n.dispatchTeamsProposal(ctx, url, p, approveLink)
	}
	// Default to Slack Block Kit / Attachments
	return n.dispatchSlackProposal(ctx, url, p, approveLink)
}

func (n *WebhookNotifier) dispatchSlackProposal(ctx context.Context, url string, p *remediation.Proposal, approveLink string) error {
	severityEmoji := "⚠️"
	color := "#DD6B20"
	if p.Diagnosis.Severity == "CRITICAL" {
		severityEmoji = "🚨"
		color = "#E53E3E"
	}

	payload := map[string]interface{}{
		"text": fmt.Sprintf("%s [%s] SRE Remediation Required: %s/%s", severityEmoji, p.Diagnosis.Severity, p.Kind, p.Name),
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": p.Diagnosis.Summary,
				"text":  p.Diagnosis.RootCause,
				"fields": []map[string]interface{}{
					{"title": "Namespace", "value": p.Namespace, "short": true},
					{"title": "Action Type", "value": string(p.Diagnosis.ActionType), "short": true},
					{"title": "Proposed Command", "value": fmt.Sprintf("`%s`", p.Diagnosis.ProposedCommand), "short": false},
					{"title": "AI Confidence", "value": fmt.Sprintf("%.0f%% via %s", p.Diagnosis.ConfidenceScore*100, p.Diagnosis.ProviderName), "short": true},
					{"title": "Review & Authorize", "value": fmt.Sprintf("<%s|Open SRE Approval Console>", approveLink), "short": false},
				},
			},
		},
	}

	return n.postJSON(ctx, url, payload)
}

func (n *WebhookNotifier) dispatchDiscordProposal(ctx context.Context, url string, p *remediation.Proposal, approveLink string) error {
	color := 0xDD6B20
	if p.Diagnosis.Severity == "CRITICAL" {
		color = 0xE53E3E
	}

	payload := map[string]interface{}{
		"content": fmt.Sprintf("🚨 **SRE Alert: %s/%s Requires Human Approval**", p.Kind, p.Name),
		"embeds": []map[string]interface{}{
			{
				"title":       p.Diagnosis.Summary,
				"description": p.Diagnosis.RootCause,
				"url":         approveLink,
				"color":       color,
				"fields": []map[string]interface{}{
					{"name": "Namespace", "value": p.Namespace, "inline": true},
					{"name": "Severity", "value": string(p.Diagnosis.Severity), "inline": true},
					{"name": "Action", "value": string(p.Diagnosis.ActionType), "inline": true},
					{"name": "Proposed Fix", "value": fmt.Sprintf("```bash\n%s\n```", p.Diagnosis.ProposedCommand), "inline": false},
					{"name": "Approve / Reject Action", "value": fmt.Sprintf("[Click here to Review on Dashboard](%s)", approveLink), "inline": false},
				},
				"footer": map[string]interface{}{
					"text": fmt.Sprintf("Kubebee SRE Agent • Diagnosed by %s", p.Diagnosis.ProviderName),
				},
			},
		},
	}

	return n.postJSON(ctx, url, payload)
}

func (n *WebhookNotifier) dispatchTeamsProposal(ctx context.Context, url string, p *remediation.Proposal, approveLink string) error {
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
	if strings.Contains(url, "discord.com") {
		payload := map[string]interface{}{
			"embeds": []map[string]interface{}{
				{
					"description": message,
					"color":       color,
				},
			},
		}
		return n.postJSON(ctx, url, payload)
	}

	// Default Slack / Mattermost compatible
	payload := map[string]interface{}{
		"text": message,
	}
	return n.postJSON(ctx, url, payload)
}

func (n *WebhookNotifier) postJSON(ctx context.Context, url string, data interface{}) error {
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook responded with status %d", resp.StatusCode)
	}
	return nil
}
