package notifier

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

type webhookRoundTripper struct {
	mu       sync.Mutex
	statuses []int
	calls    int
	bodies   [][]byte
}

func (r *webhookRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.bodies = append(r.bodies, body)
	status := http.StatusOK
	if len(r.statuses) > 0 {
		status = r.statuses[0]
		r.statuses = r.statuses[1:]
	}
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("response")),
		Request:    req,
	}, nil
}

func (r *webhookRoundTripper) snapshot() (int, []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		return r.calls, nil
	}
	return r.calls, append([]byte(nil), r.bodies[len(r.bodies)-1]...)
}

func testWebhookProposal() *remediation.Proposal {
	return &remediation.Proposal{
		ID:        "proposal-123",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "payments",
		Diagnosis: &triage.Diagnosis{
			Summary:         "pod requires review",
			RootCause:       "the pod is unhealthy",
			Severity:        scanner.SeverityHigh,
			ActionType:      triage.ActionManual,
			ProposedCommand: "kubectl describe pod payments -n default",
			ProviderName:    "rule-based",
		},
		Status: remediation.StatusPending,
	}
}

func TestWebhookProviderUsesParsedHostnameSuffixes(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want webhookProvider
	}{
		{name: "slack subdomain", url: "https://hooks.slack.com/services/team/hook", want: webhookProviderSlack},
		{name: "slack apex", url: "https://slack.com/hook", want: webhookProviderSlack},
		{name: "discord subdomain", url: "https://hooks.discord.com/api/webhooks/id/token", want: webhookProviderDiscord},
		{name: "discord legacy domain", url: "https://discordapp.com/api/webhooks/id/token", want: webhookProviderDiscord},
		{name: "teams subdomain", url: "https://outlook.office.com/webhook/hook", want: webhookProviderTeams},
		{name: "teams apex", url: "https://office.com/webhook/hook", want: webhookProviderTeams},
		{name: "lookalike discord", url: "https://evil-discord.com/hook", want: webhookProviderGeneric},
		{name: "nested lookalike discord", url: "https://discord.com.attacker.example/hook", want: webhookProviderGeneric},
		{name: "lookalike teams", url: "https://evil-office.com/hook", want: webhookProviderGeneric},
		{name: "lookalike slack", url: "https://evil-slack.com/hook", want: webhookProviderGeneric},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := webhookProviderForURL(test.url); got != test.want {
				t.Fatalf("webhookProviderForURL(%q) = %q, want %q", test.url, got, test.want)
			}
		})
	}
}

func TestWebhookProposalUsesProviderPayloadForParsedHosts(t *testing.T) {
	proposal := testWebhookProposal()
	for _, test := range []struct {
		name           string
		url            string
		mustContain    string
		mustNotContain string
	}{
		{name: "discord", url: "https://hooks.discord.com/api/webhooks/id/token", mustContain: `"embeds"`, mustNotContain: `"attachments"`},
		{name: "teams", url: "https://outlook.office.com/webhook/hook", mustContain: `"potentialAction"`, mustNotContain: `"attachments"`},
		{name: "discord lookalike remains slack", url: "https://evil-discord.com/hook", mustContain: `"attachments"`, mustNotContain: `"embeds"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &webhookRoundTripper{}
			notifier := NewWebhookNotifier("", "https://sre.example.test")
			notifier.client = &http.Client{Transport: transport}
			if err := notifier.dispatchProposal(context.Background(), test.url, notifier.sanitizeProposal(proposal)); err != nil {
				t.Fatalf("dispatchProposal() error = %v", err)
			}
			_, body := transport.snapshot()
			payload := string(body)
			if !strings.Contains(payload, test.mustContain) {
				t.Fatalf("payload = %s, missing %q", payload, test.mustContain)
			}
			if strings.Contains(payload, test.mustNotContain) {
				t.Fatalf("payload = %s, unexpectedly contains %q", payload, test.mustNotContain)
			}
		})
	}
}

func TestWebhookApprovalURLIsValidatedAndRedacted(t *testing.T) {
	const secret = "approval-url-secret-1234567890"
	transport := &webhookRoundTripper{}
	notifier := NewWebhookNotifier("", "https://sre.example.test/approve?token="+secret+"&view=compact#old", secret)
	notifier.client = &http.Client{Transport: transport}
	if err := notifier.dispatchProposal(context.Background(), "https://hooks.slack.com/services/team/hook", notifier.sanitizeProposal(testWebhookProposal())); err != nil {
		t.Fatalf("dispatchProposal() error = %v", err)
	}
	_, body := transport.snapshot()
	payload := string(body)
	if strings.Contains(payload, secret) {
		t.Fatalf("payload leaked approval URL secret: %s", payload)
	}
	if strings.Contains(payload, "#old") {
		t.Fatalf("payload retained public URL fragment: %s", payload)
	}
	if !strings.Contains(payload, "https://sre.example.test/approve") {
		t.Fatalf("payload omitted validated approval URL: %s", payload)
	}
}

func TestWebhookNotifierRejectsInvalidPublicApprovalURL(t *testing.T) {
	for _, publicURL := range []string{
		"javascript:alert(1)",
		"http://approval.example.test/console",
		"https://user:password@approval.example.test/console",
		"https://approval.example.test/console\r\nX-Injected: value",
	} {
		t.Run(publicURL, func(t *testing.T) {
			transport := &webhookRoundTripper{}
			notifier := NewWebhookNotifier("https://hooks.example.test/hook", publicURL)
			notifier.client = &http.Client{Transport: transport}
			err := notifier.NotifyProposalCreated(context.Background(), testWebhookProposal())
			if err == nil {
				t.Fatal("NotifyProposalCreated() accepted invalid public approval URL")
			}
			calls, _ := transport.snapshot()
			if calls != 0 {
				t.Fatalf("invalid public URL caused %d webhook calls", calls)
			}
		})
	}
}

func TestWebhookDeliveryRetriesTransientFailuresWithBoundedAttempts(t *testing.T) {
	transport := &webhookRoundTripper{statuses: []int{http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusNoContent}}
	notifier := NewWebhookNotifier("", "https://sre.example.test")
	notifier.client = &http.Client{Transport: transport}
	if err := notifier.dispatchGeneric(context.Background(), "https://hooks.slack.com/services/team/hook", "test", 0); err != nil {
		t.Fatalf("dispatchGeneric() error = %v", err)
	}
	calls, _ := transport.snapshot()
	if calls != 3 {
		t.Fatalf("webhook attempts = %d, want 3", calls)
	}
}

func TestWebhookDeliveryDoesNotRetryPermanentFailures(t *testing.T) {
	transport := &webhookRoundTripper{statuses: []int{http.StatusBadRequest, http.StatusOK}}
	notifier := NewWebhookNotifier("", "https://sre.example.test")
	notifier.client = &http.Client{Transport: transport}
	if err := notifier.dispatchGeneric(context.Background(), "https://hooks.slack.com/services/team/hook", "test", 0); err == nil {
		t.Fatal("dispatchGeneric() accepted permanent webhook failure")
	}
	calls, _ := transport.snapshot()
	if calls != 1 {
		t.Fatalf("webhook attempts = %d, want 1 for permanent failure", calls)
	}
}
