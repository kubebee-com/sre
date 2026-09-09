package delivery

import (
	"context"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"testing"
)

type channelRecorder struct{ generic, typed int }

func (s *channelRecorder) Send(context.Context, string, incident.Notification) error {
	s.generic++
	return nil
}
func (s *channelRecorder) SendChannel(context.Context, Channel, incident.Notification) error {
	s.typed++
	return nil
}

func TestTypedRoutesValidateDestinationAndSender(t *testing.T) {
	t.Setenv("CHANNEL_HOOK", "https://hooks.slack.com/services/a/b/c")
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, Group: "owners", Role: authorization.Owner}})
	base := Route{ID: "r", Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, RecipientGroup: "owners", Channel: &Channel{Provider: "slack", EndpointEnv: "CHANNEL_HOOK"}}
	if _, err := NewService(&postgres.Store{}, policy, []Route{base}, NewHTTPSender("https://sre.example")); err != nil {
		t.Fatal(err)
	}
	cases := []Route{base, base, base}
	cases[0].EndpointEnv = "CHANNEL_HOOK"
	bad := *base.Channel
	bad.Provider = "unknown"
	cases[1].Channel = &bad
	missing := *base.Channel
	missing.EndpointEnv = "MISSING_CHANNEL_HOOK"
	cases[2].Channel = &missing
	for i, r := range cases {
		if _, err := NewService(&postgres.Store{}, policy, []Route{r}, NewHTTPSender()); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if _, err := NewService(&postgres.Store{}, policy, []Route{base}, senderFunc(func(context.Context, string, incident.Notification) error { return nil })); err == nil {
		t.Fatal("sender without channel support accepted")
	}
}

func TestRouteSendSelectsExactlyOneTransport(t *testing.T) {
	recorder := &channelRecorder{}
	s := &Service{sender: recorder}
	if err := s.send(context.Background(), Route{Channel: &Channel{Provider: "slack"}}, incident.Notification{}); err != nil {
		t.Fatal(err)
	}
	if err := s.send(context.Background(), Route{EndpointEnv: "HOOK"}, incident.Notification{}); err != nil {
		t.Fatal(err)
	}
	if recorder.generic != 1 || recorder.typed != 1 {
		t.Fatalf("wrong dispatch %+v", recorder)
	}
	s.sender = senderFunc(func(context.Context, string, incident.Notification) error { return nil })
	if err := s.send(context.Background(), Route{Channel: &Channel{}}, incident.Notification{}); err == nil {
		t.Fatal("unsupported typed sender silently fell back")
	}
}

func TestTypedRouteCopiesCallerConfiguration(t *testing.T) {
	t.Setenv("CHANNEL_HOOK", "https://hooks.slack.com/services/a/b/c")
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, Group: "owners", Role: authorization.Owner}})
	channel := &Channel{Provider: "slack", EndpointEnv: "CHANNEL_HOOK"}
	routes := []Route{{ID: "r", Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, RecipientGroup: "owners", Channel: channel}}
	s, err := NewService(&postgres.Store{}, policy, routes, NewHTTPSender("https://sre.example"))
	if err != nil {
		t.Fatal(err)
	}
	channel.Provider = "unknown"
	routes[0].RecipientGroup = "other"
	if s.routes[0].Channel.Provider != "slack" || s.routes[0].RecipientGroup != "owners" {
		t.Fatal("caller can mutate registered route")
	}
}
