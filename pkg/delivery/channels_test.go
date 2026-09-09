package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

func channelFixture(t *testing.T, provider string) Channel {
	t.Helper()
	c := Channel{Provider: provider, EndpointEnv: "TEST_CHANNEL_ENDPOINT"}
	endpoints := map[string]string{"slack": "https://hooks.slack.com/services/T/B/secret", "teams": "https://prod-01.westus.logic.azure.com/workflows/id/triggers/manual/paths/invoke?sig=secret", "discord": "https://discord.com/api/webhooks/123/secret", "google_chat": "https://chat.googleapis.com/v1/spaces/space/messages?key=key&token=secret", "whatsapp": "https://graph.facebook.com/v23.0/123/messages", "matrix": "https://matrix.example"}
	t.Setenv(c.EndpointEnv, endpoints[provider])
	if provider == "telegram" || provider == "whatsapp" || provider == "matrix" {
		c.TokenEnv = "TEST_CHANNEL_TOKEN"
		t.Setenv(c.TokenEnv, "secret-token")
	}
	switch provider {
	case "telegram":
		c.EndpointEnv = ""
		c.Destination = "-123"
		t.Setenv(c.TokenEnv, "123:secret_token")
	case "whatsapp":
		c.Destination = "15551234567"
		c.Template = "sre_notification"
		c.Language = "en_US"
	case "matrix":
		c.Destination = "!room:matrix.example"
	}
	return c
}
func channelNotification() incident.Notification {
	return incident.Notification{ID: "message", IncidentID: "incident", Kind: "CLARIFICATION_REQUESTED", Scope: identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}}
}

func TestChannelNativeRequests(t *testing.T) {
	for _, provider := range []string{"slack", "teams", "discord", "telegram", "google_chat", "whatsapp", "matrix"} {
		t.Run(provider, func(t *testing.T) {
			c := channelFixture(t, provider)
			if err := c.Validate(); err != nil {
				t.Fatal(err)
			}
			s := NewHTTPSender("https://sre.example")
			calls := 0
			s.client.Transport = slackRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				raw, _ := io.ReadAll(r.Body)
				var p map[string]any
				if err := json.Unmarshal(raw, &p); err != nil {
					t.Fatal(err)
				}
				if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Idempotency-Key") != "message" {
					t.Fatal(r.Header)
				}
				if !strings.Contains(string(raw), "https://sre.example") || !strings.Contains(string(raw), "CLARIFICATION_REQUESTED") {
					t.Fatalf("missing projection: %s", raw)
				}
				if r.Method != "POST" && provider != "matrix" {
					t.Fatal(r.Method)
				}
				switch provider {
				case "slack":
					if p["blocks"] == nil {
						t.Fatal(p)
					}
				case "teams":
					a := p["attachments"].([]any)[0].(map[string]any)
					if a["contentType"] != "application/vnd.microsoft.card.adaptive" || a["content"].(map[string]any)["type"] != "AdaptiveCard" {
						t.Fatal(a)
					}
				case "discord":
					if p["content"] == nil || len(p["allowed_mentions"].(map[string]any)["parse"].([]any)) != 0 {
						t.Fatal(p)
					}
					if r.URL.Query().Get("wait") != "true" {
						t.Fatal(r.URL)
					}
				case "telegram":
					if r.URL.Host != "api.telegram.org" || r.URL.Path != "/bot123:secret_token/sendMessage" || p["chat_id"] != "-123" || p["parse_mode"] != nil {
						t.Fatal(r.URL, p)
					}
				case "google_chat":
					if p["text"] == nil {
						t.Fatal(p)
					}
				case "whatsapp":
					if r.Header.Get("Authorization") != "Bearer secret-token" || p["type"] != "template" || p["messaging_product"] != "whatsapp" || p["to"] != c.Destination {
						t.Fatal(p)
					}
					templ := p["template"].(map[string]any)
					if templ["name"] != c.Template || templ["language"].(map[string]any)["code"] != c.Language || len(templ["components"].([]any)[0].(map[string]any)["parameters"].([]any)) != 4 {
						t.Fatal(templ)
					}
				case "matrix":
					if r.Method != "PUT" || r.URL.Path != "/_matrix/client/v3/rooms/!room:matrix.example/send/m.room.message/message" || r.Header.Get("Authorization") != "Bearer secret-token" || p["msgtype"] != "m.text" {
						t.Fatal(r.URL, p)
					}
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
			})
			if err := s.SendChannel(context.Background(), c, channelNotification()); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatal(calls)
			}
		})
	}
}

func TestChannelRejectsInvalidConfiguration(t *testing.T) {
	cases := []struct {
		name, provider string
		change         func(*testing.T, *Channel)
	}{
		{"provider", "slack", func(t *testing.T, c *Channel) { c.Provider = "unknown" }},
		{"env name", "slack", func(t *testing.T, c *Channel) { c.EndpointEnv = "BAD=NAME" }},
		{"missing endpoint", "slack", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "") }},
		{"http", "slack", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "http://hooks.slack.com/services/a") }},
		{"foreign host", "slack", func(t *testing.T, c *Channel) {
			t.Setenv(c.EndpointEnv, "https://hooks.slack.com.evil.example/services/a")
		}},
		{"wrong slack path", "slack", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "https://hooks.slack.com/other") }},
		{"empty slack segment", "slack", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "https://hooks.slack.com/services/T//token") }},
		{"foreign discord", "discord", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "https://evil.example/api/webhooks/id/token") }},
		{"empty discord segment", "discord", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "https://discord.com/api/webhooks//token") }},
		{"foreign google", "google_chat", func(t *testing.T, c *Channel) {
			t.Setenv(c.EndpointEnv, "https://evil.example/v1/spaces/a/messages?key=a&token=b")
		}},
		{"missing google token", "google_chat", func(t *testing.T, c *Channel) {
			t.Setenv(c.EndpointEnv, "https://chat.googleapis.com/v1/spaces/a/messages?key=a")
		}},
		{"foreign teams", "teams", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "https://evil.example/invoke?sig=a") }},
		{"telegram endpoint", "telegram", func(t *testing.T, c *Channel) { c.EndpointEnv = "OTHER" }},
		{"telegram token", "telegram", func(t *testing.T, c *Channel) { t.Setenv(c.TokenEnv, "123:foo/path") }},
		{"missing token", "telegram", func(t *testing.T, c *Channel) { t.Setenv(c.TokenEnv, "") }},
		{"token name", "telegram", func(t *testing.T, c *Channel) { c.TokenEnv = "bad=name" }},
		{"destination", "telegram", func(t *testing.T, c *Channel) { c.Destination = "" }},
		{"whatsapp template", "whatsapp", func(t *testing.T, c *Channel) { c.Template = "Bad template" }},
		{"whatsapp language", "whatsapp", func(t *testing.T, c *Channel) { c.Language = "" }},
		{"whatsapp phone", "whatsapp", func(t *testing.T, c *Channel) { c.Destination = "not-phone" }},
		{"whatsapp endpoint", "whatsapp", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "https://graph.facebook.com/123/messages") }},
		{"token newline", "matrix", func(t *testing.T, c *Channel) { t.Setenv(c.TokenEnv, "token\nvalue") }},
		{"matrix room", "matrix", func(t *testing.T, c *Channel) { c.Destination = "#alias:matrix.example" }},
		{"matrix private", "matrix", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "https://127.0.0.1") }},
		{"matrix query", "matrix", func(t *testing.T, c *Channel) { t.Setenv(c.EndpointEnv, "https://matrix.example?token=secret") }},
		{"extraneous token", "slack", func(t *testing.T, c *Channel) { c.TokenEnv = "TOKEN" }},
		{"extraneous template", "telegram", func(t *testing.T, c *Channel) { c.Template = "template" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := channelFixture(t, tc.provider)
			tc.change(t, &c)
			if c.Validate() != ErrDelivery {
				t.Fatal("accepted invalid configuration")
			}
			s := NewHTTPSender("https://sre.example")
			s.client.Transport = slackRoundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("sent invalid configuration"); return nil, nil })
			if s.SendChannel(context.Background(), c, channelNotification()) != ErrDelivery {
				t.Fatal("expected redacted error")
			}
		})
	}
}
func TestChannelFailuresAreRedacted(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		failure error
	}{{"rate limit", 429, "secret", nil}, {"server", 500, "secret", nil}, {"redirect", 302, "secret", nil}, {"transport", 0, "", errors.New("secret URL")}, {"telegram rejected", 200, `{"ok":false,"description":"secret"}`, nil}, {"telegram malformed", 200, `secret`, nil}, {"telegram empty", 200, ``, nil}} {
		t.Run(tc.name, func(t *testing.T) {
			c := channelFixture(t, "telegram")
			s := NewHTTPSender("https://sre.example")
			s.client.Transport = slackRoundTrip(func(*http.Request) (*http.Response, error) {
				if tc.failure != nil {
					return nil, tc.failure
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})
			if err := s.SendChannel(context.Background(), c, channelNotification()); err != ErrDelivery {
				t.Fatalf("got %v", err)
			}
		})
	}
}
func TestChannelValidatesNotificationBeforeSending(t *testing.T) {
	for _, tc := range []struct {
		name, ui string
		mutate   func(*incident.Notification)
	}{{"ui", "http://sre.example", func(*incident.Notification) {}}, {"kind", "https://sre.example", func(n *incident.Notification) { n.Kind = "RAW_LOGS" }}, {"id", "https://sre.example", func(n *incident.Notification) { n.ID = "" }}, {"scope", "https://sre.example", func(n *incident.Notification) { n.Scope = identity.Scope{} }}} {
		t.Run(tc.name, func(t *testing.T) {
			c := channelFixture(t, "discord")
			n := channelNotification()
			tc.mutate(&n)
			s := NewHTTPSender(tc.ui)
			s.client.Transport = slackRoundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("sent invalid notification"); return nil, nil })
			if s.SendChannel(context.Background(), c, n) != ErrDelivery {
				t.Fatal("expected error")
			}
		})
	}
}

func TestChannelRequestConstructionFailure(t *testing.T) {
	c := channelFixture(t, "matrix")
	s := NewHTTPSender("https://sre.example")
	if err := s.SendChannel(nil, c, channelNotification()); err != ErrDelivery {
		t.Fatalf("nil context: %v", err)
	}
}

func TestChannelRedirectNeverForwardsCredentials(t *testing.T) {
	c := channelFixture(t, "whatsapp")
	s := NewHTTPSender("https://sre.example")
	calls := 0
	s.client.Transport = slackRoundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": []string{"https://evil.example/collect"}}, Body: io.NopCloser(strings.NewReader("secret"))}, nil
	})
	if s.SendChannel(context.Background(), c, channelNotification()) != ErrDelivery || calls != 1 {
		t.Fatalf("redirect followed: %d", calls)
	}
}

func TestChannelReadsRotatedCredentials(t *testing.T) {
	c := channelFixture(t, "matrix")
	if c.Validate() != nil {
		t.Fatal("invalid initial configuration")
	}
	t.Setenv(c.TokenEnv, "rotated-token")
	s := NewHTTPSender("https://sre.example")
	s.client.Transport = slackRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer rotated-token" {
			t.Fatal("stale credential")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	if s.SendChannel(context.Background(), c, channelNotification()) != nil {
		t.Fatal("rotated credential rejected")
	}
}

func TestChannelSupportsPowerAutomateWorkflowEndpoint(t *testing.T) {
	c := channelFixture(t, "teams")
	t.Setenv(c.EndpointEnv, "https://default123.environment.api.powerplatform.com/powerautomate/automations/direct/workflows/id/triggers/manual/paths/invoke?api-version=1&sig=secret")
	if c.Validate() != nil {
		t.Fatal("Power Automate workflow rejected")
	}
}
