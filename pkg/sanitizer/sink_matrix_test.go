package sanitizer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSinkMatrixRedactsConfiguredAndStructuredSecrets(t *testing.T) {
	secret := "sink-matrix-secret"
	redactor := NewRedactor(secret)
	input := map[string]interface{}{
		"prompt":        "inspect " + secret,
		"providerError": "token=" + secret,
		"response":      map[string]interface{}{"authorization": "Bearer " + secret, "safe": "value"},
		"output":        []interface{}{map[string]interface{}{"client_secret": secret}},
	}
	encoded, err := json.Marshal(redactor.SanitizeValue(input))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("sanitized sink output leaked secret: %s", encoded)
	}
	if got := string(redactor.SanitizeBytes([]byte(`{"password":"` + secret + `","safe":"ok"}`))); strings.Contains(got, secret) || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("sanitized bytes = %q", got)
	}
}
