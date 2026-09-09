package sanitizer

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitizeText(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean string",
			input:    "Error starting container: connection timeout to service",
			expected: "Error starting container: connection timeout to service",
		},
		{
			name:     "bearer token redaction",
			input:    "Request failed with Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDom triggers error",
			expected: "Request failed with Authorization: Bearer [REDACTED_TOKEN] triggers error",
		},
		{
			name:     "generic api key redaction",
			input:    "connecting with api_key=sk-ant-api03-abcdef1234567890 to backend",
			expected: "connecting with api_key=[REDACTED] to backend",
		},
		{
			name:     "private key redaction",
			input:    "Loaded key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----\nEnd of cert",
			expected: "Loaded key:\n[REDACTED_PRIVATE_KEY]\nEnd of cert",
		},
		{
			name:     "env secret assignment",
			input:    "export password=SuperSecretPass123! in container env",
			expected: "export password=[REDACTED] in container env",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeText(tc.input)
			if result != tc.expected {
				t.Errorf("SanitizeText() mismatch:\nExpected: %q\nGot:      %q", tc.expected, result)
			}
		})
	}
}

func TestSanitizeTextRedactsConfiguredLiteralsAndStructuredSecrets(t *testing.T) {
	configured := `literal.secret+[with](regex)`
	privateKey := "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----"
	input := strings.Join([]string{
		`Authorization: Bearer abc.def.ghi`,
		`x-api-key: sk-live-1234567890`,
		`jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature`,
		privateKey,
		`credentials: {"password": "nested-password", "client_secret": "nested-client-secret"}`,
		`configured=` + configured,
	}, "\n")

	got, report := SanitizeTextWithReport(input, configured)
	for _, raw := range []string{"abc.def.ghi", "sk-live-1234567890", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature", privateKey, "nested-password", "nested-client-secret", configured} {
		if strings.Contains(got, raw) {
			t.Errorf("SanitizeTextWithSecrets() leaked %q in %q", raw, got)
		}
	}
	for _, marker := range []string{"[REDACTED_TOKEN]", "[REDACTED_JWT]", "[REDACTED_PRIVATE_KEY]", "[REDACTED]"} {
		if !strings.Contains(got, marker) {
			t.Errorf("SanitizeTextWithSecrets() omitted marker %q from %q", marker, got)
		}
	}
	if report.RedactedCount == 0 {
		t.Fatal("SanitizeTextWithSecrets() returned an empty redaction report")
	}
}

func TestSanitizeValueRedactsNestedMapsWithoutChangingShape(t *testing.T) {
	input := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name":   "web",
			"labels": map[string]interface{}{"team": "platform"},
		},
		"credentials": map[string]interface{}{
			"username": "service-user",
			"password": "nested-password",
		},
		"passwords": "plural-password",
		"tokens":    []interface{}{"plural-token"},
		"api_keys":  []interface{}{"plural-api-key"},
		"secrets":   map[string]interface{}{"value": "plural-secret"},
		"containers": []interface{}{map[string]interface{}{
			"env": map[string]interface{}{
				"API_KEY": "nested-api-key",
				"entry":   map[string]interface{}{"name": "DB_PASSWORD", "value": "nested-env-password"},
			},
		}},
	}

	got := SanitizeValue(input)
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(SanitizeValue()) error = %v", err)
	}
	serialized := string(encoded)
	for _, raw := range []string{"nested-password", "nested-api-key", "nested-env-password", "plural-password", "plural-token", "plural-api-key", "plural-secret"} {
		if strings.Contains(serialized, raw) {
			t.Errorf("SanitizeValue() leaked %q in %s", raw, serialized)
		}
	}
	for _, marker := range []string{`"metadata"`, `"labels"`, `"containers"`, `"[REDACTED]"`} {
		if !strings.Contains(serialized, marker) {
			t.Errorf("SanitizeValue() lost expected structure/marker %q in %s", marker, serialized)
		}
	}
}

func TestRedactorSanitizeValueRedactsConfiguredLiteralsInMapKeys(t *testing.T) {
	secret := "configured-map-key-secret"
	input := map[string]interface{}{
		"metadata": map[string]interface{}{secret: "value"},
	}

	encoded, err := json.Marshal(NewRedactor(secret).SanitizeValue(input))
	if err != nil {
		t.Fatalf("json.Marshal(SanitizeValue()) error = %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("SanitizeValue() leaked configured map key: %s", encoded)
	}
}
