package authorization

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"strings"
	"testing"
	"time"
)

func TestQueuedIdentityIsBoundEncryptedAndRestartInvalidated(t *testing.T) {
	scope := identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}
	bindings := []Binding{{Scope: scope, Group: "private-group", Role: Investigator}}
	policy, _ := NewPolicy(bindings)
	p := identity.Principal{ID: "actor", Issuer: "https://idp", Groups: []string{"private-group"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	grant, err := policy.SealPrincipal(p, scope, Investigate)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(grant, "private-group") {
		t.Fatal("raw group persisted")
	}
	if got, err := policy.OpenPrincipal(grant, scope, Investigate); err != nil || got.ID != p.ID {
		t.Fatal("valid authority lost")
	}
	other := scope
	other.ClusterID = "other"
	if _, err := policy.OpenPrincipal(grant, other, Investigate); err == nil {
		t.Fatal("crossscope grant")
	}
	if _, err := policy.OpenPrincipal(grant, scope, Approve); err == nil {
		t.Fatal("write authority escalated")
	}
	restarted, _ := NewPolicy(bindings)
	if _, err := restarted.OpenPrincipal(grant, scope, Investigate); err == nil {
		t.Fatal("restore resurrected queued authority")
	}
}
