package orchestrator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFalcoWebhookHandler(t *testing.T) {
	srv := &Server{
		config: Config{
			FalcoSecret: "secret-falco-12345",
		},
	}

	// 1. Missing auth token
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/falco", bytes.NewReader([]byte(`{"rule":"test"}`)))
	w := httptest.NewRecorder()
	srv.falcoWebhook(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
	}

	// 2. Invalid auth token
	req = httptest.NewRequest(http.MethodPost, "/api/webhooks/falco", bytes.NewReader([]byte(`{"rule":"test"}`)))
	req.Header.Set("X-Falco-Token", "wrong-token")
	w = httptest.NewRecorder()
	srv.falcoWebhook(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got %d", w.Code)
	}

	// 3. Valid auth token with single event
	eventJSON := `{
		"output": "10:00:00.000: Warning Shell spawned in container (k8s.ns=default k8s.pod=nginx-xyz)",
		"priority": "Warning",
		"rule": "Terminal shell in container",
		"output_fields": {
			"k8s.ns.name": "default",
			"k8s.pod.name": "nginx-xyz"
		}
	}`
	req = httptest.NewRequest(http.MethodPost, "/api/webhooks/falco?organization_id=myorg&cluster_id=prod&application_id=payments", bytes.NewReader([]byte(eventJSON)))
	req.Header.Set("X-Falco-Token", "secret-falco-12345")
	w = httptest.NewRecorder()
	srv.falcoWebhook(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["status"] != "accepted" {
		t.Errorf("expected status accepted, got %v", resp["status"])
	}
	if resp["events_processed"].(float64) != 1 {
		t.Errorf("expected 1 processed event, got %v", resp["events_processed"])
	}

	// 4. Valid auth token with array of events via Bearer token
	batchJSON := `[
		{"output": "Alert 1", "priority": "Error", "rule": "Rule 1"},
		{"output": "Alert 2", "priority": "Critical", "rule": "Rule 2"}
	]`
	req = httptest.NewRequest(http.MethodPost, "/api/webhooks/falco?organization_id=myorg&cluster_id=prod&application_id=payments", bytes.NewReader([]byte(batchJSON)))
	req.Header.Set("Authorization", "Bearer secret-falco-12345")
	w = httptest.NewRecorder()
	srv.falcoWebhook(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for batch, got %d: %s", w.Code, w.Body.String())
	}

	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["events_processed"].(float64) != 2 {
		t.Errorf("expected 2 processed events, got %v", resp["events_processed"])
	}
}
