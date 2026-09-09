package notifier

import (
	"strings"
	"testing"
)

func TestWebhookURLGetterMasksUnconfiguredStructuralSecrets(t *testing.T) {
	notifier := NewWebhookNotifier("https://user:password@hooks.example.invalid/api/webhooks/12345678901234567890/opaque-token-1234567890?token=query-token-1234567890&safe=keep", "https://sre.example.invalid")
	got := notifier.GetWebhookURL()
	for _, secret := range []string{"password", "12345678901234567890", "opaque-token-1234567890", "query-token-1234567890"} {
		if strings.Contains(got, secret) {
			t.Fatalf("GetWebhookURL() leaked structural secret %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "safe=keep") {
		t.Fatalf("GetWebhookURL() removed safe query data: %s", got)
	}
}
