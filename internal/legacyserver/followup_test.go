package legacyserver

import (
	"net/http"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/notifier"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/triage"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestConfigAPIDoesNotExposeWebhookURLSecrets(t *testing.T) {
	const canary = "config-url-query-canary-1234567890"
	n := notifier.NewWebhookNotifier("https://hooks.example.invalid/services/team/opaque-path-token-1234567890?token="+canary, "https://sre.example.invalid")
	s := NewServer(0, nil, triage.NewRuleBasedProvider(), remediation.NewEngine(k8sfake.NewSimpleClientset()), n)
	rr := serveTestRequest(testHandler(t, s), http.MethodGet, "/api/config", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/config status = %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), canary) || strings.Contains(rr.Body.String(), "opaque-path-token-1234567890") {
		t.Fatalf("GET /api/config exposed webhook URL secret: %s", rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "webhook_configured") {
		t.Fatalf("GET /api/config omitted configuration state: %s", rr.Body.String())
	}
}
