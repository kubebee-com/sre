package sanitizer

import (
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
