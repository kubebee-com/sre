package delivery

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"testing"
	"time"
)

func TestDeliveryRejectsUnsafeOrRawDestinations(t *testing.T) {
	for _, endpoint := range []string{"http://example.com", "https://user:secret@example.com", "https://169.254.169.254/latest/meta-data"} {
		if ValidateEndpoint(endpoint) == nil {
			t.Fatalf("unsafe endpoint %s", endpoint)
		}
	}
	sender := NewHTTPSender()
	if sender.Send(context.Background(), "http://example.com", incident.Notification{Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}}) == nil {
		t.Fatal("unsafe delivery")
	}
}

type senderFunc func(context.Context, string, incident.Notification) error

func (f senderFunc) Send(ctx context.Context, endpoint string, n incident.Notification) error {
	return f(ctx, endpoint, n)
}
func TestDurableDeliveryDeduplicatesAndReauthorizes(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}, {Scope: scope, Group: "viewers", Role: authorization.Viewer}})
	route := Route{ID: "owners", Scope: scope, RecipientGroup: "owners", EndpointEnv: "SRE_TEST_NOTIFICATION_ENDPOINT"}
	t.Setenv(route.EndpointEnv, "https://example.com/webhook")
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.Enqueue("event", "INCIDENT_CREATED", json.RawMessage(`{"incident_id":"i"}`))
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s, err := NewService(db, policy, []Route{route}, senderFunc(func(_ context.Context, _ string, n incident.Notification) error {
		calls++
		if n.IncidentID != "i" {
			t.Fatal("wrong incident")
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Dispatch(ctx, route); err != nil {
		t.Fatal(err)
	}
	if err := s.Dispatch(ctx, route); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("event duplicated", calls)
	}
	var id string
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		ns, err := tx.Notifications("", 10)
		if err != nil {
			return err
		}
		if len(ns) != 1 || ns[0].State != "DELIVERED" || ns[0].Attempts != 1 {
			t.Fatal("delivery not persisted")
		}
		id = ns[0].ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := identity.Principal{ID: "engineer", Issuer: "https://idp", Groups: []string{"owners"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	viewer := p
	viewer.Groups = []string{"viewers"}
	if err := s.Acknowledge(ctx, viewer, scope, id); err == nil {
		t.Fatal("viewer could suppress owner notification")
	}
	if err := s.Acknowledge(ctx, p, scope, id); err != nil {
		t.Fatal(err)
	}
	denied, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "other", Role: authorization.Owner}})
	s.Policy = denied
	if err := s.Dispatch(ctx, route); err == nil {
		t.Fatal("revoked destination authorization accepted")
	}
	if calls != 1 {
		t.Fatal("revoked destination received event")
	}
}

func TestNewRouteDoesNotReplayHistoricalEvents(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.Enqueue("old", "INCIDENT_CREATED", json.RawMessage(`{"incident_id":"i"}`))
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.RegisterNotificationRoute("new-owner") }); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.Enqueue("new", "INCIDENT_CREATED", json.RawMessage(`{"incident_id":"i"}`)); err != nil {
			return err
		}
		if err := tx.MaterializeNotifications("new-owner"); err != nil {
			return err
		}
		ns, err := tx.Notifications("", 100)
		if err == nil && len(ns) != 1 {
			t.Fatal("new route replayed historical events", len(ns))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDurableTypedChannelUsesSharedQueue(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}})
	t.Setenv("TYPED_SLACK_HOOK", "https://hooks.slack.com/services/T/B/token")
	route := Route{ID: "typed", Scope: scope, RecipientGroup: "owners", Channel: &Channel{Provider: "slack", EndpointEnv: "TYPED_SLACK_HOOK"}}
	recorder := &channelRecorder{}
	service, err := NewService(db, policy, []Route{route}, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RegisterRoutes(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.Enqueue("event", "INCIDENT_CREATED", json.RawMessage(`{"incident_id":"i"}`))
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := service.Dispatch(ctx, route); err != nil {
			t.Fatal(err)
		}
	}
	if recorder.typed != 1 || recorder.generic != 0 {
		t.Fatalf("typed queue delivery: %+v", recorder)
	}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		ns, err := tx.Notifications("", 10)
		if err != nil {
			return err
		}
		if len(ns) != 1 || ns[0].State != "DELIVERED" || ns[0].Attempts != 1 {
			t.Fatalf("wrong persisted delivery: %+v", ns)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
