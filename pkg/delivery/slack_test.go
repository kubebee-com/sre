package delivery

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSlackProjectionLinksToHumanAuthority(t *testing.T) {
	n := incident.Notification{ID: "message", Scope: identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}, IncidentID: "incident", Kind: "CLARIFICATION_REQUESTED"}
	raw, err := SlackPayload("https://sre.example", n)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		t.Fatal("invalid JSON")
	}
	s := string(raw)
	if !strings.Contains(s, "https://sre.example") || strings.Contains(s, "approve\"") || strings.Contains(s, "action_id") || strings.Contains(s, "response_url") {
		t.Fatalf("unsafe authority: %s", raw)
	}
	if _, err := SlackPayload("javascript:alert(1)", n); err == nil {
		t.Fatal("unsafe UI URL")
	}
	n.Kind = "RAW_LOGS"
	if _, err := SlackPayload("https://sre.example", n); err == nil {
		t.Fatal("unprojected event")
	}
}

type slackRoundTrip func(*http.Request) (*http.Response, error)

func (f slackRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestSlackTransportUsesDurableNotificationIdentity(t *testing.T) {
	n := incident.Notification{ID: "message", Scope: identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}, IncidentID: "incident", Kind: "CLARIFICATION_REQUESTED"}
	calls := 0
	sender := NewHTTPSender("https://sre.example")
	sender.client = &http.Client{Transport: slackRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), "blocks") || r.Header.Get("Idempotency-Key") != n.ID {
			t.Fatal("adapter lost native payload or durable identity")
		}
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader("rate limited"))}, nil
	})}
	if err := sender.Send(context.Background(), "https://hooks.slack.com/services/test", n); err != ErrDelivery {
		t.Fatalf("retryable failure lost: %v", err)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}
