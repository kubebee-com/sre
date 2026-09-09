package sanitizer

import (
	"strings"
	"testing"
)

func TestSanitizeStructuredTextRedactsNestedJSONAndYAML(t *testing.T) {
	redactor := NewRedactor("configured-structured-secret")
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "json",
			input: `{"metadata":{"name":"DB_PASSWORD","value":"json-password"},"safe":"keep"}`,
			want:  []string{"json-password", `"safe":"keep"`, `"value":"[REDACTED]"`},
		},
		{
			name:  "yaml",
			input: "- name: DB_PASSWORD\n  value: yaml-password\n- name: REGION\n  value: us-east-1\n",
			want:  []string{"yaml-password", "name: REGION", "value: us-east-1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactor.SanitizeStructuredText(tc.input)
			if strings.Contains(got, tc.want[0]) {
				t.Fatalf("structured sanitizer leaked secret %q: %s", tc.want[0], got)
			}
			for _, marker := range tc.want[1:] {
				if !strings.Contains(got, marker) {
					t.Errorf("structured sanitizer omitted safe marker %q: %s", marker, got)
				}
			}
		})
	}
}

func TestSanitizeURLRedactsStructuralSecrets(t *testing.T) {
	redactor := NewRedactor()
	input := "https://user:password@example.invalid/services/team/opaque-path-token-1234567890?channel=ops&token=query-token-1234567890&safe=keep"
	got := redactor.SanitizeURL(input)
	for _, secret := range []string{"password", "opaque-path-token-1234567890", "query-token-1234567890"} {
		if strings.Contains(got, secret) {
			t.Fatalf("URL sanitizer leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "example.invalid") || !strings.Contains(got, "safe=keep") {
		t.Fatalf("URL sanitizer removed safe routing data: %s", got)
	}
}

func TestSafeLogValueRedactsAndFlattensUntrustedText(t *testing.T) {
	redactor := NewRedactor("log-configured-secret")
	got := redactor.SafeLogValue("issue\nlog-configured-secret\r\nattacker")
	if strings.Contains(got, "log-configured-secret") || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("SafeLogValue() returned unsafe log text: %q", got)
	}
}

func TestStructuredTextSanitizesAllEmbeddedDocumentsAndSurroundingText(t *testing.T) {
	input := "API_KEY=outer-secret\n```json\n" + `{"env":[{"name":"DB_PASSWORD","value":"first-private-value"}]}` + "\n```\nNext\n```json\n" + `{"env":[{"name":"DB_PASSWORD","value":"second-private-value"}]}` + "\n```\nkeep this instruction"
	got := NewRedactor().SanitizeStructuredText(input)
	for _, secret := range []string{"outer-secret", "first-private-value", "second-private-value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("embedded document secret survived: %s", secret)
		}
	}
	if !strings.Contains(got, "keep this instruction") {
		t.Fatal("safe instructions lost")
	}
}
