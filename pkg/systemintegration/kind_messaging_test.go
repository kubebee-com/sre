package systemintegration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/kubebee-com/sre/pkg/delivery"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

// Only the final outbound transport is substituted. Dispatch still uses the real
// durable PostgreSQL outbox, leases and delivery acknowledgements.
type kindNotificationSink struct{ sent []incident.Notification }

func (s *kindNotificationSink) Send(_ context.Context, _ string, n incident.Notification) error {
	s.sent = append(s.sent, n)
	return nil
}

type kindMessaging struct {
	t       *testing.T
	ctx     context.Context
	server  *httptest.Server
	scope   identity.Scope
	service *delivery.Service
	route   delivery.Route
	sink    *kindNotificationSink
}

func (m *kindMessaging) api(method, path string, body any, want int) []byte {
	m.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		m.t.Fatal(err)
	}
	query := url.Values{"organization_id": {m.scope.OrganizationID}, "cluster_id": {m.scope.ClusterID}, "application_id": {m.scope.ApplicationID}}
	req, err := http.NewRequestWithContext(m.ctx, method, m.server.URL+path+"?"+query.Encode(), strings.NewReader(string(raw)))
	if err != nil {
		m.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer fixture-owner-a")
	req.Header.Set("Content-Type", "application/json")
	return m.send(req, want)
}
func (m *kindMessaging) send(req *http.Request, want int) []byte {
	m.t.Helper()
	res, err := m.server.Client().Do(req)
	if err != nil {
		m.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		m.t.Fatal(err)
	}
	if res.StatusCode != want {
		m.t.Fatalf("%s %s: status %d want %d: %s", req.Method, req.URL.Path, res.StatusCode, want, raw)
	}
	for _, canary := range []string{"alice", "private-workload"} {
		if strings.Contains(string(raw), canary) {
			m.t.Fatal("customer canary reached operator response")
		}
	}
	return raw
}
func (m *kindMessaging) callback(user, command string, forged, accepted bool) {
	m.t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	body := url.Values{"team_id": {"kind-team"}, "channel_id": {"kind-room"}, "user_id": {user}, "command": {"/sre"}, "text": {command}}.Encode()
	req, err := http.NewRequestWithContext(m.ctx, "POST", m.server.URL+"/channels/kind-ops/events", strings.NewReader(body))
	if err != nil {
		m.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	mac := hmac.New(sha256.New, []byte("synthetic-kind-signing-secret"))
	mac.Write([]byte("v0:" + ts + ":" + body))
	signature := hex.EncodeToString(mac.Sum(nil))
	if forged {
		signature = strings.Repeat("0", 64)
	}
	req.Header.Set("X-Slack-Signature", "v0="+signature)
	if forged {
		m.send(req, http.StatusUnauthorized)
		return
	}
	raw := m.send(req, http.StatusOK)
	expected := "Command rejected"
	if accepted {
		expected = "Command accepted"
	}
	if !strings.Contains(string(raw), expected) {
		m.t.Fatalf("unexpected callback result: %s", raw)
	}
}
func (m *kindMessaging) state(id, want string, version int64) incident.Action {
	m.t.Helper()
	var actions []incident.Action
	if err := json.Unmarshal(m.api("GET", "/api/actions", nil, 200), &actions); err != nil {
		m.t.Fatal(err)
	}
	for _, a := range actions {
		if a.Plan.ID == id {
			if a.State != want || a.Version != version {
				m.t.Fatalf("action state/version %s/%d want %s/%d", a.State, a.Version, want, version)
			}
			return a
		}
	}
	m.t.Fatal("action missing from API")
	return incident.Action{}
}
func (m *kindMessaging) dispatch() []incident.Notification {
	m.t.Helper()
	for i := 0; i < 100; i++ {
		before := len(m.sink.sent)
		if err := m.service.Dispatch(m.ctx, m.route); err != nil {
			m.t.Fatal(err)
		}
		if len(m.sink.sent) == before {
			break
		}
		if i == 99 {
			m.t.Fatal("notification backlog failed to drain")
		}
	}
	var notices []incident.Notification
	if err := json.Unmarshal(m.api("GET", "/api/notifications", nil, 200), &notices); err != nil {
		m.t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, n := range notices {
		if n.Scope != m.scope || n.RouteID != m.route.ID || n.State != "DELIVERED" || n.Attempts != 1 || seen[n.EventID] {
			m.t.Fatalf("invalid durable delivery: %+v", n)
		}
		seen[n.EventID] = true
	}
	if len(notices) != len(m.sink.sent) {
		m.t.Fatal("durable notifications and local deliveries differ")
	}
	return notices
}
func (m *kindMessaging) propose(request execution.ProposeRequest) incident.Action {
	m.t.Helper()
	m.dispatch()
	before := len(m.sink.sent)
	var a incident.Action
	if err := json.Unmarshal(m.api("POST", "/api/actions", request, 201), &a); err != nil {
		m.t.Fatal(err)
	}
	if a.Hash == "" || a.Hash != a.Plan.Hash() || a.Plan.EvidenceHash != request.EvidenceHash {
		m.t.Fatal("proposal omitted exact evidence/plan commitment")
	}
	m.state(a.Plan.ID, "PROPOSED", 1)
	notices := m.dispatch()
	if len(m.sink.sent) != before+1 {
		m.t.Fatal("proposal did not produce exactly one delivery")
	}
	n := m.sink.sent[before]
	if n.Kind != "ACTION_UPDATED" || n.IncidentID != request.IncidentID {
		m.t.Fatal("wrong proposal notification")
	}
	m.callback("owner", "ack "+n.ID, false, true)
	m.state(a.Plan.ID, "PROPOSED", 1)
	notices = m.dispatch()
	for _, got := range notices {
		if got.ID == n.ID {
			if got.AcknowledgedBy != "slack-owner-a" {
				m.t.Fatal("mapped acknowledgement actor missing")
			}
			return a
		}
	}
	m.t.Fatal("acknowledged notification missing")
	return incident.Action{}
}
func (m *kindMessaging) audit(dsn, id string, expected []string) {
	m.t.Helper()
	conn, err := pgx.Connect(m.ctx, dsn)
	if err != nil {
		m.t.Fatal(err)
	}
	defer conn.Close(m.ctx)
	rows, err := conn.Query(m.ctx, `SELECT envelope->>'state' FROM enterprise_core.action_events WHERE organization_id=$1 AND cluster_id=$2 AND application_id=$3 AND action_id=$4 ORDER BY version`, m.scope.OrganizationID, m.scope.ClusterID, m.scope.ApplicationID, id)
	if err != nil {
		m.t.Fatal(err)
	}
	var states []string
	for rows.Next() {
		var state string
		if err = rows.Scan(&state); err != nil {
			m.t.Fatal(err)
		}
		states = append(states, state)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		m.t.Fatal(err)
	}
	if strings.Join(states, ",") != strings.Join(expected, ",") {
		m.t.Fatalf("audit transitions %v want %v", states, expected)
	}
	var delivered int
	err = conn.QueryRow(m.ctx, `SELECT count(*) FROM enterprise_core.notifications n JOIN enterprise_core.outbox o ON o.organization_id=n.organization_id AND o.cluster_id=n.cluster_id AND o.application_id=n.application_id AND o.id=n.event_id WHERE n.organization_id=$1 AND n.cluster_id=$2 AND n.application_id=$3 AND n.route_id=$4 AND n.kind='ACTION_UPDATED' AND n.state='DELIVERED' AND o.payload->>'action_id'=$5`, m.scope.OrganizationID, m.scope.ClusterID, m.scope.ApplicationID, m.route.ID, id).Scan(&delivered)
	if err != nil || delivered != len(expected) {
		m.t.Fatalf("action notification audit count %d want %d: %v", delivered, len(expected), err)
	}
}
