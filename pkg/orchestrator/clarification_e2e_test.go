package orchestrator

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/delivery"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/interaction"
	"github.com/kubebee-com/sre/pkg/messaging"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
)

type clarificationDelivery struct {
	mu            sync.Mutex
	notifications []incident.Notification
}

func (d *clarificationDelivery) Send(_ context.Context, _ string, n incident.Notification) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.notifications = append(d.notifications, n)
	return nil
}

// This is the complete clarification/acknowledgement HTTP path. Only the IdP and
// outbound IM boundary are substituted; policy, handlers, outbox, delivery leases,
// request signatures, optimistic updates and audit persistence are real.
func TestMessagingClarificationAndAcknowledgementE2E(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real PostgreSQL required; run scripts/ci/messaging-e2e.sh")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, err := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}, {Scope: scope, Group: "viewers", Role: authorization.Viewer}})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLARIFICATION_E2E_ENDPOINT", "https://example.com/webhook")
	t.Setenv("CLARIFICATION_E2E_SECRET", "synthetic-signing-secret")
	route := delivery.Route{ID: "owners", Scope: scope, RecipientGroup: "owners", EndpointEnv: "CLARIFICATION_E2E_ENDPOINT"}
	sent := &clarificationDelivery{}
	services := make([]*delivery.Service, 2)
	servers := make([]*httptest.Server, 2)
	for i := range servers {
		services[i], err = delivery.NewService(db, policy, []delivery.Route{route}, sent)
		if err != nil {
			t.Fatal(err)
		}
		if err := services[i].RegisterRoutes(ctx); err != nil {
			t.Fatal(err)
		}
		app, err := New(Config{DB: db, Policy: policy, PublicURL: "https://sre.example", Notifications: services[i], Verifier: verifierFunc(func(_ context.Context, token string) (identity.Principal, error) {
			if token != "owners" && token != "viewers" {
				return identity.Principal{}, identity.ErrUnauthenticated
			}
			return identity.Principal{ID: "ui-" + token, Issuer: "https://test-idp", Groups: []string{token}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
		}), Messaging: []messaging.Config{{ID: "ops", Provider: "slack", SecretEnv: "CLARIFICATION_E2E_SECRET", AccountID: "team", ConversationID: "room", Scope: scope, Users: []messaging.User{{ExternalID: "owner", PrincipalID: "im-owner", Groups: []string{"owners"}}, {ExternalID: "viewer", PrincipalID: "im-viewer", Groups: []string{"viewers"}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		servers[i] = httptest.NewServer(app)
		defer servers[i].Close()
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		return tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	query := "?" + url.Values{"organization_id": {scope.OrganizationID}, "cluster_id": {scope.ClusterID}, "application_id": {scope.ApplicationID}}.Encode()
	request := func(replica int, method, path, token string, body any, want int) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		r, err := http.NewRequest(method, servers[replica].URL+path, bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		response, err := servers[replica].Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s: %d, want %d: %s", method, path, response.StatusCode, want, data)
		}
		return data
	}
	callback := func(replica int, user, command string, wantAccepted bool) {
		t.Helper()
		body := url.Values{"team_id": {"team"}, "channel_id": {"room"}, "user_id": {user}, "command": {"/sre"}, "text": {command}}.Encode()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte("synthetic-signing-secret"))
		mac.Write([]byte("v0:" + ts + ":" + body))
		r, err := http.NewRequest("POST", servers[replica].URL+"/channels/ops/events", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Slack-Request-Timestamp", ts)
		r.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
		response, err := servers[replica].Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		if response.StatusCode != 200 || strings.Contains(string(raw), "Command accepted.") != wantAccepted {
			t.Fatalf("callback %q: %d %s", command, response.StatusCode, raw)
		}
	}
	question := interaction.Request{Scope: scope, ID: "question", IncidentID: "incident", Kind: interaction.Clarification, Question: "IMPACT", Version: 1, Status: "PENDING", ExpiresAt: time.Now().Add(time.Hour)}
	request(0, "POST", "/api/interactions"+query, "viewers", question, 403)
	request(0, "POST", "/api/interactions"+query, "owners", question, 201)
	// Another replica consumes the committed outbox and the original replica cannot redeliver it.
	for _, i := range []int{1, 0} {
		if err := services[i].Dispatch(ctx, route); err != nil {
			t.Fatal(err)
		}
	}
	sent.mu.Lock()
	captured := append([]incident.Notification(nil), sent.notifications...)
	sent.mu.Unlock()
	if len(captured) != 1 || captured[0].Kind != "CLARIFICATION_REQUESTED" || captured[0].IncidentID != "incident" || captured[0].Scope != scope {
		t.Fatalf("wrong delivery: %+v", captured)
	}
	notificationID := captured[0].ID
	request(0, "GET", "/api/notifications"+query, "agent", nil, 401)
	request(0, "POST", "/api/notifications/"+notificationID+"/acknowledge"+query, "viewers", nil, 403)
	callback(1, "viewer", "ack "+notificationID, false)
	callback(1, "owner", "ack "+notificationID, true)
	callback(0, "owner", "ack "+notificationID, true)
	// Acknowledging the alert must not answer its clarification.
	var questions []interaction.Request
	if err := json.Unmarshal(request(0, "GET", "/api/interactions"+query, "owners", nil, 200), &questions); err != nil {
		t.Fatal(err)
	}
	if len(questions) != 1 || questions[0].Status != "PENDING" || questions[0].Version != 1 || questions[0].ActorID != "" {
		t.Fatalf("ack changed question: %+v", questions)
	}
	callback(0, "viewer", "answer question 1 UNKNOWN", false)
	callback(1, "owner", "answer question 2 UNKNOWN", false)
	callback(1, "owner", "answer question 1 INVALID", false)
	callback(1, "owner", "answer question 1 USER_VISIBLE", true)
	callback(0, "owner", "answer question 1 UNKNOWN", false)
	request(0, "POST", "/api/interactions/question/answer"+query, "owners", map[string]any{"version": 1, "answer": "UNKNOWN"}, 409)
	if err := json.Unmarshal(request(0, "GET", "/api/interactions"+query, "owners", nil, 200), &questions); err != nil {
		t.Fatal(err)
	}
	if len(questions) != 1 || questions[0].Status != "ANSWERED" || questions[0].Version != 2 || questions[0].Answer != "USER_VISIBLE" || questions[0].ActorID != "im-owner" {
		t.Fatalf("wrong final answer: %+v", questions)
	}
	var notifications []incident.Notification
	if err := json.Unmarshal(request(0, "GET", "/api/notifications"+query, "owners", nil, 200), &notifications); err != nil {
		t.Fatal(err)
	}
	if len(notifications) != 1 || notifications[0].AcknowledgedBy != "im-owner" || notifications[0].State != "DELIVERED" {
		t.Fatalf("wrong notification state: %+v", notifications)
	}
	// Read the durable audit source, independently of the HTTP response projection.
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, kind := range []string{"CLARIFICATION_REQUESTED", "CLARIFICATION_ANSWERED", "NOTIFICATION_ACKNOWLEDGED"} {
		var count int
		err := conn.QueryRow(ctx, `SELECT count(*) FROM enterprise_core.outbox WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND kind=$4`, scope.OrganizationID, scope.ClusterID, scope.ApplicationID, kind).Scan(&count)
		if err != nil || count != 1 {
			t.Fatalf("%s audit count %d: %v", kind, count, err)
		}
	}
}
