package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

type slackPayload struct {
	Text        string       `json:"text"`
	Attachments []attachment `json:"attachments,omitempty"`
}

type attachment struct {
	Color  string  `json:"color"`
	Title  string  `json:"title"`
	Text   string  `json:"text"`
	Fields []field `json:"fields,omitempty"`
}

type field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func (n *WebhookNotifier) NotifyProposalCreated(ctx context.Context, p *remediation.Proposal) error {
	if n.webhookURL == "" {
		return nil
	}

	title := fmt.Sprintf("[%s] SRE Remediation Required: %s/%s", p.Diagnosis.Severity, p.Kind, p.Name)
	approveLink := fmt.Sprintf("%s/#proposal-%s", n.publicURL, p.ID)

	payload := slackPayload{
		Text: title,
		Attachments: []attachment{
			{
				Color: "#e53e3e", // Red / warning
				Title: p.Diagnosis.Summary,
				Text:  p.Diagnosis.RootCause,
				Fields: []field{
					{Title: "Namespace", Value: p.Namespace, Short: true},
					{Title: "Action Type", Value: string(p.Diagnosis.ActionType), Short: true},
					{Title: "Proposed Fix", Value: fmt.Sprintf("`%s`", p.Diagnosis.ProposedCommand), Short: false},
					{Title: "Dashboard Approval Link", Value: approveLink, Short: false},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch webhook: %w", err)
	}
	defer resp.Body.Close()

	return nil
}
