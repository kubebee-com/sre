package orchestrator

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
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
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/messaging"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
)

type approvalNotificationSink struct{ sent []incident.Notification }

func (s *approvalNotificationSink) Send(_ context.Context, _ string, n incident.Notification) error {
	s.sent = append(s.sent, n)
	return nil
}

// This exercises real HTTP routing, provider authentication, policy, PostgreSQL
// transitions and the durable delivery worker. Only identity verification and the
// final notification transport are substitutes; no execution runs on a cluster.
func TestMessagingApprovalE2E(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SRE_ENTERPRISE_TEST_DATABASE_URL required for real PostgreSQL E2E")
	}
	for _, provider := range []string{"slack", "discord", "telegram"} {
		t.Run(provider, func(t *testing.T) {
			ctx := context.Background()
			db, err := postgres.Open(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			audit, err := pgx.Connect(ctx, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer audit.Close(ctx)
			scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
			policy, err := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "admins", Role: authorization.Administrator}, {Scope: scope, Group: "owners", Role: authorization.Owner}, {Scope: scope, Group: "investigators", Role: authorization.Investigator}})
			if err != nil {
				t.Fatal(err)
			}
			actor := func(group string) identity.Principal {
				return identity.Principal{ID: group, Issuer: "https://idp.example", Groups: []string{group}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
			}
			f, err := fleet.NewService(db, policy, "authority")
			if err != nil {
				t.Fatal(err)
			}
			enroll := func(id, role string) fleet.Credential {
				b, e := f.Bootstrap(ctx, actor("admins"), scope, id, "cluster", role)
				if e != nil {
					t.Fatal(e)
				}
				c, e := f.Enroll(ctx, scope, b.Token, "cluster", role)
				if e != nil {
					t.Fatal(e)
				}
				return c
			}
			collector, executor := enroll("collector", fleet.Collector), enroll("executor", fleet.Executor)
			observation := privacy.Observation{Code: privacy.CrashLoop, ResourceHandle: strings.Repeat("a", 32), Target: &privacy.Target{Kind: "Pod", UID: "11111111-1111-1111-1111-111111111111", ResourceVersion: "7", Commitment: strings.Repeat("b", 64)}, Source: &privacy.Provenance{AgentID: collector.Agent.ID, Generation: collector.Agent.Generation, Epoch: f.Epoch, ReportID: identity.NewID()}, ObservedAt: time.Now().Add(-time.Second), ValidUntil: time.Now().Add(5 * time.Minute)}
			raw, _ := json.Marshal(observation)
			evidence := incident.Item{Scope: scope, IncidentID: "incident", ID: "evidence", Version: 1, Kind: incident.Evidence, Body: raw, ObservedAt: observation.ObservedAt, ValidUntil: observation.ValidUntil}
			evidence.Seal()
			sink := &approvalNotificationSink{}
			t.Setenv("SRE_APPROVAL_E2E_ENDPOINT", "https://notifications.example/events")
			route := delivery.Route{ID: "ops", Scope: scope, RecipientGroup: "owners", EndpointEnv: "SRE_APPROVAL_E2E_ENDPOINT"}
			notifications, err := delivery.NewService(db, policy, []delivery.Route{route}, sink)
			if err != nil {
				t.Fatal(err)
			}
			if err = notifications.RegisterRoutes(ctx); err != nil {
				t.Fatal(err)
			}
			if err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
				if e := tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()}); e != nil {
					return e
				}
				return tx.PutItem(evidence)
			}); err != nil {
				t.Fatal(err)
			}
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("SRE_APPROVAL_E2E_SECRET", "synthetic_secret_123")
			channel := messaging.Config{ID: "ops", Provider: provider, SecretEnv: "SRE_APPROVAL_E2E_SECRET", PublicKey: hex.EncodeToString(pub), AccountID: "account", ConversationID: "-42", Scope: scope, Users: []messaging.User{{ExternalID: "123", PrincipalID: "mapped-owner", Groups: []string{"owners"}}, {ExternalID: "456", PrincipalID: "mapped-investigator", Groups: []string{"investigators"}}}}
			config := Config{DB: db, Policy: policy, Fleet: f, Execution: &execution.Service{Fleet: f, Enabled: true}, Notifications: notifications, PublicURL: "https://sre.example", Messaging: []messaging.Config{channel}, Verifier: verifierFunc(func(_ context.Context, token string) (identity.Principal, error) {
				if token != "investigator-token" {
					return identity.Principal{}, identity.ErrUnauthenticated
				}
				return actor("investigators"), nil
			})}
			replicas := make([]*httptest.Server, 2)
			for i := range replicas {
				s, e := New(config)
				if e != nil {
					t.Fatal(e)
				}
				replicas[i] = httptest.NewServer(s)
				defer replicas[i].Close()
			}
			query := "?" + url.Values{"organization_id": {scope.OrganizationID}, "cluster_id": {scope.ClusterID}, "application_id": {scope.ApplicationID}}.Encode()
			request := func(method, path, token string, body any, want int) []byte {
				t.Helper()
				var r io.Reader
				if body != nil {
					b, e := json.Marshal(body)
					if e != nil {
						t.Fatal(e)
					}
					r = strings.NewReader(string(b))
				}
				req, e := http.NewRequest(method, replicas[0].URL+path+query, r)
				if e != nil {
					t.Fatal(e)
				}
				req.Header.Set("Authorization", "Bearer "+token)
				req.Header.Set("Content-Type", "application/json")
				res, e := replicas[0].Client().Do(req)
				if e != nil {
					t.Fatal(e)
				}
				defer res.Body.Close()
				b, e := io.ReadAll(res.Body)
				if e != nil {
					t.Fatal(e)
				}
				if res.StatusCode != want {
					t.Fatalf("%s %s: status %d want %d: %s", method, path, res.StatusCode, want, b)
				}
				return b
			}
			proposal := execution.ProposeRequest{IncidentID: "incident", Kind: "REPLACE_POD", Evidence: incident.ItemRef{ID: evidence.ID, Version: 1}, EvidenceHash: evidence.Hash, ExecutorID: executor.Agent.ID}
			propose := func() incident.Action {
				t.Helper()
				var a incident.Action
				if e := json.Unmarshal(request("POST", "/api/actions", "investigator-token", proposal, 201), &a); e != nil {
					t.Fatal(e)
				}
				return a
			}
			state := func(id, want string, version int64) incident.Action {
				t.Helper()
				var actions []incident.Action
				if e := json.Unmarshal(request("GET", "/api/actions", "investigator-token", nil, 200), &actions); e != nil {
					t.Fatal(e)
				}
				for _, a := range actions {
					if a.Plan.ID == id {
						if a.State != want || a.Version != version {
							t.Fatalf("action %s state/version %s/%d want %s/%d", id, a.State, a.Version, want, version)
						}
						return a
					}
				}
				t.Fatalf("action %s missing", id)
				return incident.Action{}
			}
			a := propose()
			a = state(a.Plan.ID, "PROPOSED", 1)
			if a.Hash == "" || a.Hash != a.Plan.Hash() {
				t.Fatal("API omitted exact plan commitment")
			}
			claimPath := "/agent/actions/" + a.Plan.ID + "/claim"
			request("POST", claimPath, executor.Token, nil, 409)
			// Provider callbacks contain real HMAC/Ed25519 signatures or Telegram's
			// configured webhook secret, and travel over HTTP into each replica.
			callback := func(replica int, user, room, command string, forged bool) (int, string, error) {
				req := approvalCallback(provider, priv, replicas[replica].URL, user, room, command, forged)
				res, e := replicas[replica].Client().Do(req)
				if e != nil {
					return 0, "", e
				}
				defer res.Body.Close()
				b, e := io.ReadAll(res.Body)
				return res.StatusCode, string(b), e
			}
			// Deliver the approval request before receiving the human response.
			if err := notifications.Dispatch(ctx, route); err != nil {
				t.Fatal(err)
			}
			if len(sink.sent) != 1 || sink.sent[0].Kind != "ACTION_UPDATED" || sink.sent[0].IncidentID != "incident" {
				t.Fatalf("proposal did not notify operator: %+v", sink.sent)
			}
			noticeID := sink.sent[0].ID
			code, body, e := callback(1, "123", "-42", "ack "+noticeID, false)
			if e != nil || code != 200 {
				t.Fatalf("acknowledge proposal: %d %s %v", code, body, e)
			}
			state(a.Plan.ID, "PROPOSED", 1)
			request("POST", claimPath, executor.Token, nil, 409)
			var pendingNotices []incident.Notification
			if err := json.Unmarshal(request("GET", "/api/notifications", "investigator-token", nil, 200), &pendingNotices); err != nil {
				t.Fatal(err)
			}
			if len(pendingNotices) != 1 || pendingNotices[0].AcknowledgedBy != "mapped-owner" {
				t.Fatalf("acknowledgement missing: %+v", pendingNotices)
			}
			for _, bad := range []struct {
				name, user, room, hash string
				forged                 bool
				status                 int
			}{{"mapped nonapprover", "456", "-42", a.Hash, false, 200}, {"wrong hash", "123", "-42", strings.Repeat("0", 64), false, 200}, {"forged authentication", "123", "-42", a.Hash, true, 401}, {"wrong room", "123", "999", a.Hash, false, 401}} {
				t.Run(bad.name, func(t *testing.T) {
					code, body, e := callback(0, bad.user, bad.room, "approve "+a.Plan.ID+" "+bad.hash, bad.forged)
					if e != nil || code != bad.status {
						t.Fatalf("callback: %d %s %v", code, body, e)
					}
					if bad.status == 200 && provider != "telegram" && !strings.Contains(body, "rejected") {
						t.Fatalf("denial not acknowledged: %s", body)
					}
					state(a.Plan.ID, "PROPOSED", 1)
				})
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					code, body, e := callback(i%2, "123", "-42", "approve "+a.Plan.ID+" "+a.Hash, false)
					if e != nil || code != 200 {
						t.Errorf("concurrent callback: %d %s %v", code, body, e)
					}
				}(i)
			}
			wg.Wait()
			approved := state(a.Plan.ID, "APPROVED", 2)
			if approved.ApprovedBy != "mapped-owner" {
				t.Fatalf("approval actor: %s", approved.ApprovedBy)
			}
			request("POST", claimPath, collector.Token, nil, 401)
			var claim execution.Claim
			if err = json.Unmarshal(request("POST", claimPath, executor.Token, nil, 200), &claim); err != nil {
				t.Fatal(err)
			}
			state(a.Plan.ID, "SUBMITTED", 3)
			request("POST", claimPath, executor.Token, nil, 409)
			receiptPath := "/agent/actions/" + a.Plan.ID + "/receipt"
			request("POST", receiptPath, executor.Token, map[string]string{"receipt_token": strings.Repeat("0", 64), "outcome": "APPLIED"}, 409)
			receipt := map[string]string{"receipt_token": claim.ReceiptToken, "outcome": "APPLIED"}
			request("POST", receiptPath, executor.Token, receipt, 200)
			request("POST", receiptPath, executor.Token, receipt, 200)
			done := state(a.Plan.ID, "APPLIED", 4)
			if done.OutcomeCode != "APPLIED" || done.ApprovedBy != "mapped-owner" {
				t.Fatalf("lost outcome or actor: %+v", done)
			}
			rejected := propose()
			code, body, err = callback(1, "123", "-42", "reject "+rejected.Plan.ID, false)
			if err != nil || code != 200 {
				t.Fatalf("reject: %d %s %v", code, body, err)
			}
			state(rejected.Plan.ID, "CANCELLED", 2)
			request("POST", "/agent/actions/"+rejected.Plan.ID+"/claim", executor.Token, nil, 409)
			_, _, err = callback(0, "123", "-42", "approve "+rejected.Plan.ID+" "+rejected.Hash, false)
			if err != nil {
				t.Fatal(err)
			}
			state(rejected.Plan.ID, "CANCELLED", 2)
			for _, check := range []struct {
				id     string
				states []string
			}{{a.Plan.ID, []string{"PROPOSED", "APPROVED", "SUBMITTED", "APPLIED"}}, {rejected.Plan.ID, []string{"PROPOSED", "CANCELLED"}}} {
				rows, e := audit.Query(ctx, `SELECT envelope->>'state' FROM enterprise_core.action_events WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND action_id=$4 ORDER BY version`, scope.OrganizationID, scope.ClusterID, scope.ApplicationID, check.id)
				if e != nil {
					t.Fatal(e)
				}
				var states []string
				for rows.Next() {
					var s string
					if e = rows.Scan(&s); e != nil {
						t.Fatal(e)
					}
					states = append(states, s)
				}
				e = rows.Err()
				rows.Close()
				if e != nil {
					t.Fatal(e)
				}
				if strings.Join(states, ",") != strings.Join(check.states, ",") {
					t.Fatalf("audit transitions %v want %v", states, check.states)
				}
			}
			// Each of the six committed action updates is delivered once despite replay.
			for i := 0; i < 10; i++ {
				if err = notifications.Dispatch(ctx, route); err != nil {
					t.Fatal(err)
				}
			}
			var notices []incident.Notification
			if err = json.Unmarshal(request("GET", "/api/notifications", "investigator-token", nil, 200), &notices); err != nil {
				t.Fatal(err)
			}
			updates := 0
			seen := map[string]bool{}
			for _, n := range notices {
				if n.Kind == "ACTION_UPDATED" {
					updates++
				}
				if n.State != "DELIVERED" || n.Attempts != 1 || n.RouteID != route.ID || n.Scope != scope || n.IncidentID != "incident" || seen[n.EventID] {
					t.Fatalf("invalid durable notification: %+v", n)
				}
				seen[n.EventID] = true
			}
			if updates != 6 || len(sink.sent) != len(notices) || len(notices) == 0 {
				t.Fatalf("action notices=%d sends=%d durable=%d", updates, len(sink.sent), len(notices))
			}
		})
	}
}

func approvalCallback(provider string, priv ed25519.PrivateKey, base, user, room, command string, forged bool) *http.Request {
	now := time.Now().Unix()
	ts := strconv.FormatInt(now, 10)
	var body string
	switch provider {
	case "slack":
		body = url.Values{"team_id": {"account"}, "channel_id": {room}, "user_id": {user}, "command": {"/sre"}, "text": {command}}.Encode()
	case "discord":
		b, _ := json.Marshal(map[string]any{"type": 2, "guild_id": "account", "channel_id": room, "member": map[string]any{"user": map[string]any{"id": user}}, "data": map[string]any{"name": "sre", "options": []any{map[string]any{"name": "command", "type": 3, "value": command}}}})
		body = string(b)
	case "telegram":
		chat, _ := strconv.ParseInt(room, 10, 64)
		uid, _ := strconv.ParseInt(user, 10, 64)
		b, _ := json.Marshal(map[string]any{"update_id": 1, "message": map[string]any{"date": now, "chat": map[string]any{"id": chat}, "from": map[string]any{"id": uid}, "text": "/sre " + command}})
		body = string(b)
	}
	req, _ := http.NewRequest("POST", base+"/channels/ops/events", strings.NewReader(body))
	switch provider {
	case "slack":
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Slack-Request-Timestamp", ts)
		mac := hmac.New(sha256.New, []byte("synthetic_secret_123"))
		mac.Write([]byte("v0:" + ts + ":" + body))
		req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	case "discord":
		req.Header.Set("X-Signature-Timestamp", ts)
		req.Header.Set("X-Signature-Ed25519", hex.EncodeToString(ed25519.Sign(priv, []byte(ts+body))))
	case "telegram":
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", "synthetic_secret_123")
	}
	if forged {
		req.Header = make(http.Header)
	}
	return req
}
