package orchestrator

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/delivery"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/interaction"
	"github.com/kubebee-com/sre/pkg/messaging"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMessagingConfigRequiresApplicationAndMappedAccess(t *testing.T) {
	valid := `{"applications":[{"scope":{"organization_id":"o","cluster_id":"c","application_id":"a"},"owner_group":"team","approver_groups":["approvers"]}],"bindings":[],"providers":[],"messaging":[{"id":"ops","provider":"slack","secret_env":"SRE_SLACK_SIGNING_SECRET","account_id":"workspace","conversation_id":"channel","scope":{"organization_id":"o","cluster_id":"c","application_id":"a"},"users":[{"external_id":"user","principal_id":"engineer","groups":["approvers"]}]}]}`
	if _, err := ReadDeploymentConfig(strings.NewReader(valid)); err != nil {
		t.Fatalf("scoped approver mapping rejected: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(valid, `"groups":["approvers"]`, `"groups":["unbound"]`, 1),
		strings.Replace(valid, `"conversation_id":"channel","scope":{"organization_id":"o","cluster_id":"c","application_id":"a"}`, `"conversation_id":"channel","scope":{"organization_id":"o","cluster_id":"c","application_id":"other"}`, 1),
	} {
		if _, err := ReadDeploymentConfig(strings.NewReader(bad)); err == nil {
			t.Fatal("unscoped messaging accepted")
		}
	}
}

func TestMessagingCommandChecksPermissionBeforeDependencies(t *testing.T) {
	scope := identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}
	policy, err := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "viewers", Role: authorization.Viewer}, {Scope: scope, Group: "approvers", Role: authorization.Approver}})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{config: Config{Policy: policy}}
	p := identity.Principal{ID: "engineer", Issuer: "messaging", Groups: []string{"viewers"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	for _, verb := range []string{"approve", "reject", "answer", "ack"} {
		if err := s.messagingCommand(context.Background(), p, scope, messaging.Command{Verb: verb, ID: "record", Value: "value", Version: 1}); !errors.Is(err, authorization.ErrForbidden) {
			t.Fatalf("%s bypassed policy: %v", verb, err)
		}
	}
	p.Groups = []string{"approvers"}
	if err := s.messagingCommand(context.Background(), p, scope, messaging.Command{Verb: "answer", ID: "record", Value: "value", Version: 1}); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("approver answered interaction: %v", err)
	}
	other := scope
	other.ApplicationID = "other"
	if err := s.messagingCommand(context.Background(), p, other, messaging.Command{Verb: "approve", ID: "record"}); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("cross-scope approval accepted: %v", err)
	}
	if err := s.messagingCommand(context.Background(), p, scope, messaging.Command{Verb: "diagnose", ID: "record"}); !errors.Is(err, postgres.ErrInvalid) {
		t.Fatalf("unexpected verb accepted: %v", err)
	}
}

func TestMessagingCommandMissingServicesReturnsUnavailable(t *testing.T) {
	scope := identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}})
	p := identity.Principal{ID: "engineer", Issuer: "messaging", Groups: []string{"owners"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	for _, config := range []Config{{Policy: policy}, {Policy: policy, Notifications: &delivery.Service{}, Execution: &execution.Service{Enabled: true, Fleet: &fleet.Service{Policy: policy}}}} {
		s := &Server{config: config}
		for _, verb := range []string{"approve", "reject", "answer", "ack"} {
			if err := s.messagingCommand(context.Background(), p, scope, messaging.Command{Verb: verb, ID: "record", Value: "value", Version: 1}); !errors.Is(err, postgres.ErrUnavailable) {
				t.Fatalf("%s nil service: %v", verb, err)
			}
		}
	}
}

func TestMessagingRouteUsesNativeAuthentication(t *testing.T) {
	t.Setenv("SRE_SLACK_SIGNING_SECRET", "secret")
	scope := identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}})
	config := Config{DB: &postgres.Store{}, Policy: policy, Verifier: loginVerifier{}, PublicURL: "https://sre.example", Messaging: []messaging.Config{{ID: "ops", Provider: "slack", SecretEnv: "SRE_SLACK_SIGNING_SECRET", AccountID: "workspace", ConversationID: "channel", Scope: scope, Users: []messaging.User{{ExternalID: "user", PrincipalID: "engineer", Groups: []string{"owners"}}}}}}
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.ServeHTTP(response, httptest.NewRequest("POST", "/channels/ops/events", strings.NewReader(`{"type":"url_verification","challenge":"hello"}`)))
	if response.Code != 401 {
		t.Fatalf("unsigned channel request: %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "sign in required") {
		t.Fatal("platform callback routed through OIDC")
	}
	config.Messaging[0].SecretEnv = "MISSING_MESSAGING_SECRET"
	t.Setenv("MISSING_MESSAGING_SECRET", "")
	if _, err := New(config); err == nil {
		t.Fatal("channel without authentication secret accepted")
	}
}

func TestMessagingAnswerPreservesVersionAndActor(t *testing.T) {
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
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}})
	p := identity.Principal{ID: "mapped-engineer", Issuer: "messaging", Groups: []string{"owners"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	s := &Server{config: Config{DB: db, Policy: policy}}
	err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.CreateInteraction(interaction.Request{Scope: scope, ID: "question", IncidentID: "incident", Kind: interaction.Clarification, Question: "IMPACT", Version: 1, Status: "PENDING", ExpiresAt: time.Now().Add(time.Hour)}, "owner")
	})
	if err != nil {
		t.Fatal(err)
	}
	command := messaging.Command{Verb: "answer", ID: "question", Value: "UNKNOWN", Version: 1}
	if err := s.messagingCommand(ctx, p, scope, command); err != nil {
		t.Fatal(err)
	}
	if err := s.messagingCommand(ctx, p, scope, command); !errors.Is(err, postgres.ErrConflict) {
		t.Fatalf("replayed answer: %v", err)
	}
	err = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		requests, err := tx.Interactions("", 50)
		if err != nil {
			return err
		}
		if len(requests) != 1 || requests[0].ActorID != p.ID {
			t.Fatalf("mapped actor missing: %+v", requests)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMessagingStorageFailureIsRetryable(t *testing.T) {
	scope := identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}})
	p := identity.Principal{ID: "engineer", Issuer: "messaging", Groups: []string{"owners"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	s := &Server{config: Config{Policy: policy}}
	err := s.messagingCommand(context.Background(), p, scope, messaging.Command{Verb: "answer", ID: "request", Version: 1, Value: "UNKNOWN"})
	if !errors.Is(err, messaging.ErrRetryable) || !errors.Is(err, postgres.ErrUnavailable) {
		t.Fatalf("storage failure is not retryable: %v", err)
	}
	p.Groups = []string{"unknown"}
	err = s.messagingCommand(context.Background(), p, scope, messaging.Command{Verb: "answer", ID: "request", Version: 1, Value: "UNKNOWN"})
	if !errors.Is(err, authorization.ErrForbidden) || errors.Is(err, messaging.ErrRetryable) {
		t.Fatalf("policy denial became retryable: %v", err)
	}
}
