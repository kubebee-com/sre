package interaction

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"testing"
	"time"
)

func TestClosedClarificationVocabulary(t *testing.T) {
	r := Request{ID: "request", Scope: identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}, IncidentID: "incident", Kind: Clarification, Question: "CHANGE_CONTEXT", Version: 1, Status: "PENDING", ExpiresAt: time.Now().Add(time.Hour)}
	if r.Validate(time.Now()) != nil {
		t.Fatal("valid request denied")
	}
	if r.Accepts("yes") || r.Accepts("APPROVE") {
		t.Fatal("chat approval accepted")
	}
	if !r.Accepts("UNKNOWN") {
		t.Fatal("enumerated response rejected")
	}
	r.Question = "paste logs"
	if r.Validate(time.Now()) == nil {
		t.Fatal("free text accepted")
	}
	r.Question = "CHANGE_CONTEXT"
	r.ExpiresAt = time.Now().Add(-time.Second)
	if r.Validate(time.Now()) == nil {
		t.Fatal("expired request accepted")
	}
}
