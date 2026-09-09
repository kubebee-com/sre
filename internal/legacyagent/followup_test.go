package legacyagent

import (
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/config"
)

func TestSanitizeLogUsesConfiguredRedactorAndSafeFormatter(t *testing.T) {
	secret := "main-log-configured-secret"
	databaseURL := "postgres://db_user:db-password@db.example.test:5432/sre?sslmode=require"
	cfg := &config.Config{
		LLMAPIKey:          secret,
		LLMHeaders:         []string{"X-Token:header-configured-secret"},
		WebhookURL:         "https://hooks.example.test/runtime-webhook-secret",
		APIToken:           "runtime-api-secret",
		CacheEncryptionKey: "runtime-cache-secret",
		DatabaseURL:        databaseURL,
	}
	got := sanitizeLog(cfg, "issue\n"+secret+"\r\nattacker header-configured-secret "+databaseURL+" db_user:db-password db-password runtime-webhook-secret runtime-api-secret runtime-cache-secret")
	if strings.Contains(got, secret) || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("sanitizeLog() returned unsafe value: %q", got)
	}
	for _, leaked := range []string{"header-configured-secret", databaseURL, "db_user:db-password", "db-password", "runtime-webhook-secret", "runtime-api-secret", "runtime-cache-secret"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("sanitizeLog() leaked %q in %q", leaked, got)
		}
	}
}
