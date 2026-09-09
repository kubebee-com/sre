package delivery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
)

type notificationE2E struct {
	t      *testing.T
	ctx    context.Context
	db     *postgres.Store
	sql    *pgx.Conn
	scope  identity.Scope
	policy *authorization.Policy
}

func newNotificationE2E(t *testing.T) *notificationE2E {
	t.Helper()
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SRE_ENTERPRISE_TEST_DATABASE_URL required for real PostgreSQL notification E2E")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, err := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}})
	if err != nil {
		t.Fatal(err)
	}
	return &notificationE2E{t: t, ctx: ctx, db: db, sql: conn, scope: scope, policy: policy}
}
func (f *notificationE2E) enqueue(id string) {
	f.t.Helper()
	err := f.db.Transact(f.ctx, f.scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: f.scope, ID: id, Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.Enqueue("event_"+id, "INCIDENT_CREATED", json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"private_details":"DO_NOT_SEND_INCIDENT_SECRET"}`, id)))
	})
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *notificationE2E) service(sender *HTTPSender, routes ...Route) *Service {
	f.t.Helper()
	s, err := NewService(f.db, f.policy, routes, sender)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := s.RegisterRoutes(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	return s
}
func (f *notificationE2E) dispatch(s *Service, r Route) {
	f.t.Helper()
	if err := s.Dispatch(f.ctx, r); err != nil {
		f.t.Fatal(err)
	}
}
func (f *notificationE2E) notifications() []incident.Notification {
	f.t.Helper()
	var ns []incident.Notification
	err := f.db.Transact(f.ctx, f.scope, func(tx *postgres.Tx) error { var err error; ns, err = tx.Notifications("", 100); return err })
	if err != nil {
		f.t.Fatal(err)
	}
	return ns
}
func (f *notificationE2E) advance(column, id string) {
	f.t.Helper()
	if column != "next_attempt_at" && column != "created_at" {
		f.t.Fatal("invalid clock column")
	}
	tag, err := f.sql.Exec(f.ctx, `UPDATE enterprise_core.notifications SET `+column+`=now()-interval '2 minutes' WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND id=$4`, f.scope.OrganizationID, f.scope.ClusterID, f.scope.ApplicationID, id)
	if err != nil || tag.RowsAffected() != 1 {
		f.t.Fatalf("advance notification clock: %v rows=%d", err, tag.RowsAffected())
	}
}

// Only the network dial is redirected. Real adapters still validate public provider
// URLs, construct requests, perform TLS HTTP I/O, and interpret provider responses.
func notificationE2ESender(t *testing.T, handler http.HandlerFunc) *HTTPSender {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	// Authenticate the local fixture certificate while preserving the provider Host.
	transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	sender := NewHTTPSender("https://sre.example.com")
	sender.client.Transport = transport
	return sender
}
func notificationE2ESlack(t *testing.T, scope identity.Scope) Route {
	t.Helper()
	t.Setenv("SRE_E2E_NOTIFICATION_ENDPOINT", "https://hooks.slack.com/services/T/B/test-token")
	return Route{ID: "owners", Scope: scope, RecipientGroup: "owners", Channel: &Channel{Provider: "slack", EndpointEnv: "SRE_E2E_NOTIFICATION_ENDPOINT"}}
}

func TestNotificationE2EProviderDelivery(t *testing.T) {
	cases := []struct{ provider, endpoint, token, destination, host, path string }{
		{"slack", "https://hooks.slack.com/services/T/B/test-token", "", "", "hooks.slack.com", "/services/T/B/test-token"},
		{"teams", "https://test.logic.azure.com/workflows/test/triggers/manual/paths/invoke?sig=test-signature", "", "", "test.logic.azure.com", "/workflows/test/triggers/manual/paths/invoke"},
		{"discord", "https://discord.com/api/webhooks/123/test-token", "", "", "discord.com", "/api/webhooks/123/test-token"},
		{"telegram", "", "123456:test-token", "-123456", "api.telegram.org", "/bot123456:test-token/sendMessage"},
		{"google_chat", "https://chat.googleapis.com/v1/spaces/test/messages?key=test-key&token=test-token", "", "", "chat.googleapis.com", "/v1/spaces/test/messages"},
		{"whatsapp", "https://graph.facebook.com/v23.0/123456/messages", "test-bearer", "15551234567", "graph.facebook.com", "/v23.0/123456/messages"},
		{"matrix", "https://matrix.example.com", "test-bearer", "!room:example.com", "matrix.example.com", "/_matrix/client/v3/rooms/!room:example.com/send/m.room.message/"},
	}
	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			f := newNotificationE2E(t)
			t.Setenv("SRE_E2E_ENDPOINT", tc.endpoint)
			t.Setenv("SRE_E2E_TOKEN", tc.token)
			c := Channel{Provider: tc.provider, EndpointEnv: "SRE_E2E_ENDPOINT", Destination: tc.destination}
			if tc.token != "" {
				c.TokenEnv = "SRE_E2E_TOKEN"
			}
			if tc.provider == "telegram" {
				c.EndpointEnv = ""
			}
			if tc.provider == "whatsapp" {
				c.Template = "sre_notification"
				c.Language = "en_US"
			}
			var calls atomic.Int32
			requestIDs := make(chan string, 10)
			sender := notificationE2ESender(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				requestID := r.Header.Get("Idempotency-Key")
				requestIDs <- requestID
				method := http.MethodPost
				if tc.provider == "matrix" {
					method = http.MethodPut
				}
				if r.TLS == nil || r.Host != tc.host || r.Method != method || r.Header.Get("Content-Type") != "application/json" || requestID == "" {
					t.Errorf("invalid native HTTP request: %s %s host=%s", r.Method, r.URL, r.Host)
				}
				wantPath := tc.path
				if tc.provider == "matrix" {
					wantPath += requestID
				}
				if r.URL.Path != wantPath {
					t.Errorf("path=%s want %s", r.URL.Path, wantPath)
				}
				if tc.provider == "discord" && r.URL.Query().Get("wait") != "true" {
					t.Error("Discord response confirmation missing")
				}
				if (tc.provider == "matrix" || tc.provider == "whatsapp") && r.Header.Get("Authorization") != "Bearer "+tc.token {
					t.Error("bearer authorization missing")
				}
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				var body map[string]any
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Error(err)
					return
				}
				q := url.Values{"organization_id": {f.scope.OrganizationID}, "cluster_id": {f.scope.ClusterID}, "application_id": {f.scope.ApplicationID}, "incident_id": {"incident"}}
				link := "https://sre.example.com/?" + q.Encode()
				var decoded any
				_ = json.Unmarshal(raw, &decoded)
				if !notificationE2EContains(decoded, link) || !strings.Contains(string(raw), requestID) || strings.Contains(string(raw), "DO_NOT_SEND_INCIDENT_SECRET") {
					t.Errorf("notification projection or authenticated link invalid: %s", raw)
				}
				switch tc.provider {
				case "slack":
					if body["text"] != "SRE notification: INCIDENT_CREATED" || body["unfurl_links"] != false || len(body["blocks"].([]any)) != 2 {
						t.Error("invalid Slack payload")
					}
				case "teams":
					if body["type"] != "message" {
						t.Error("invalid Teams envelope")
					}
					card := body["attachments"].([]any)[0].(map[string]any)
					if card["contentType"] != "application/vnd.microsoft.card.adaptive" || card["content"].(map[string]any)["type"] != "AdaptiveCard" {
						t.Error("invalid adaptive card")
					}
				case "discord":
					if len(body["allowed_mentions"].(map[string]any)["parse"].([]any)) != 0 || body["content"] == nil {
						t.Error("invalid Discord content or mention suppression")
					}
				case "telegram":
					if body["chat_id"] != tc.destination || body["link_preview_options"].(map[string]any)["is_disabled"] != true {
						t.Error("invalid Telegram payload")
					}
				case "google_chat":
					if body["text"] == nil {
						t.Error("missing Google Chat text")
					}
				case "whatsapp":
					template := body["template"].(map[string]any)
					params := template["components"].([]any)[0].(map[string]any)["parameters"].([]any)
					if body["messaging_product"] != "whatsapp" || body["to"] != tc.destination || body["type"] != "template" || template["name"] != c.Template || template["language"].(map[string]any)["code"] != c.Language || len(params) != 4 {
						t.Error("invalid WhatsApp template")
					}
					for i, want := range []string{"INCIDENT_CREATED", "incident", requestID, link} {
						if params[i].(map[string]any)["text"] != want {
							t.Errorf("template parameter %d invalid", i)
						}
					}
				case "matrix":
					if body["msgtype"] != "m.text" || body["body"] == nil {
						t.Error("invalid Matrix message")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"ok":true}`)
			})
			route := Route{ID: "owners", Scope: f.scope, RecipientGroup: "owners", Channel: &c}
			service := f.service(sender, route)
			f.enqueue("incident")
			f.dispatch(service, route)
			f.dispatch(service, route)
			ns := f.notifications()
			if calls.Load() != 1 || len(ns) != 1 {
				t.Fatalf("calls=%d notifications=%+v", calls.Load(), ns)
			}
			if ns[0].State != "DELIVERED" || ns[0].Attempts != 1 || ns[0].ID != <-requestIDs || ns[0].DeliveredAt == nil {
				t.Fatalf("delivery not durable: %+v", ns[0])
			}
		})
	}
}
func notificationE2EContains(v any, want string) bool {
	switch x := v.(type) {
	case string:
		return strings.Contains(x, want)
	case []any:
		for _, item := range x {
			if notificationE2EContains(item, want) {
				return true
			}
		}
	case map[string]any:
		for _, item := range x {
			if notificationE2EContains(item, want) {
				return true
			}
		}
	}
	return false
}

func TestNotificationE2ERetryAndExhaustion(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f := newNotificationE2E(t)
			route := notificationE2ESlack(t, f.scope)
			var calls atomic.Int32
			var fail atomic.Bool
			fail.Store(true)
			sender := notificationE2ESender(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if fail.Load() {
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusOK)
			})
			s := f.service(sender, route)
			f.enqueue("retry")
			f.dispatch(s, route)
			ns := f.notifications()
			if len(ns) != 1 || ns[0].State != "PENDING" || ns[0].Attempts != 1 || ns[0].DeliveredAt != nil {
				t.Fatalf("failed attempt not persisted: %+v", ns)
			}
			f.dispatch(s, route)
			if calls.Load() != 1 {
				t.Fatal("retried before eligible time")
			}
			f.advance("next_attempt_at", ns[0].ID)
			fail.Store(false)
			f.dispatch(s, route)
			f.dispatch(s, route)
			ns = f.notifications()
			if calls.Load() != 2 || ns[0].State != "DELIVERED" || ns[0].Attempts != 2 {
				t.Fatalf("retry did not deliver once: calls=%d %+v", calls.Load(), ns)
			}
			fail.Store(true)
			f.enqueue("exhaust")
			f.dispatch(s, route)
			var failed incident.Notification
			for _, n := range f.notifications() {
				if n.IncidentID == "exhaust" {
					failed = n
				}
			}
			for attempt := 2; attempt <= 8; attempt++ {
				f.advance("next_attempt_at", failed.ID)
				f.dispatch(s, route)
			}
			for _, n := range f.notifications() {
				if n.ID == failed.ID {
					failed = n
				}
			}
			if failed.State != "FAILED" || failed.Attempts != 8 || failed.DeliveredAt != nil {
				t.Fatalf("exhaustion not durable: %+v", failed)
			}
			f.advance("next_attempt_at", failed.ID)
			f.dispatch(s, route)
			if calls.Load() != 10 {
				t.Fatalf("terminal failure resent: calls=%d", calls.Load())
			}
		})
	}
}

func TestNotificationE2EConcurrentReplicas(t *testing.T) {
	f := newNotificationE2E(t)
	route := notificationE2ESlack(t, f.scope)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32
	sender := notificationE2ESender(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusOK)
	})
	releaseRequest := sync.OnceFunc(func() { close(release) })
	defer releaseRequest()
	first := f.service(sender, route)
	replicaDB, err := postgres.Open(f.ctx, os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replicaDB.Close)
	second, err := NewService(replicaDB, f.policy, []Route{route}, sender)
	if err != nil {
		t.Fatal(err)
	}
	f.enqueue("concurrent")
	result := make(chan error, 1)
	go func() { result <- first.Dispatch(f.ctx, route) }()
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal("first replica never sent")
	}
	ns := f.notifications()
	if len(ns) != 1 || ns[0].State != "SENDING" || ns[0].Attempts != 1 {
		t.Fatalf("lease missing while HTTP request active: %+v", ns)
	}
	f.dispatch(second, route)
	if calls.Load() != 1 {
		t.Fatal("second replica sent active lease")
	}
	releaseRequest()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	f.dispatch(second, route)
	ns = f.notifications()
	if calls.Load() != 1 || ns[0].State != "DELIVERED" || ns[0].Attempts != 1 {
		t.Fatalf("replica duplicate: calls=%d %+v", calls.Load(), ns)
	}
}

func TestNotificationE2EEscalationAcknowledgementAndRevocation(t *testing.T) {
	for _, ack := range []bool{false, true} {
		t.Run(fmt.Sprintf("acknowledged_%t", ack), func(t *testing.T) {
			f := newNotificationE2E(t)
			route := notificationE2ESlack(t, f.scope)
			target := route
			target.ID = "oncall"
			route.EscalationRouteID = target.ID
			route.EscalateAfterSeconds = 60
			var calls atomic.Int32
			sender := notificationE2ESender(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) })
			s := f.service(sender, route, target)
			f.enqueue("escalate")
			f.dispatch(s, route)
			f.dispatch(s, target)
			ns := f.notifications()
			if len(ns) != 1 || calls.Load() != 1 {
				t.Fatal("escalated before deadline")
			}
			if ack {
				p := identity.Principal{ID: "engineer", Issuer: "https://idp.example.com", Groups: []string{"owners"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
				if err := s.Acknowledge(f.ctx, p, f.scope, ns[0].ID); err != nil {
					t.Fatal(err)
				}
			}
			f.advance("created_at", ns[0].ID)
			f.dispatch(s, route)
			f.dispatch(s, target)
			f.dispatch(s, route)
			f.dispatch(s, target)
			ns = f.notifications()
			want := 2
			if ack {
				want = 1
			}
			if len(ns) != want || int(calls.Load()) != want {
				t.Fatalf("escalation ack=%t calls=%d notifications=%+v", ack, calls.Load(), ns)
			}
			for _, n := range ns {
				if n.State != "DELIVERED" || n.Attempts != 1 {
					t.Fatalf("invalid escalation delivery %+v", n)
				}
				if ack && n.AcknowledgedBy != "engineer" {
					t.Fatal("acknowledgement not durable")
				}
			}
			f.enqueue("revoked")
			denied, err := authorization.NewPolicy([]authorization.Binding{{Scope: f.scope, Group: "other", Role: authorization.Owner}})
			if err != nil {
				t.Fatal(err)
			}
			s.Policy = denied
			if err := s.Dispatch(f.ctx, route); err != authorization.ErrForbidden {
				t.Fatalf("revoked recipient accepted: %v", err)
			}
			if int(calls.Load()) != want {
				t.Fatal("revoked recipient received HTTP notification")
			}
		})
	}
}
