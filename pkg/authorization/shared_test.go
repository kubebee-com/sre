package authorization

import (
	"bytes"
	"github.com/kubebee-com/sre/pkg/identity"
	"testing"
	"time"
)

func TestSharedGrantKeySupportsReplicaAndRejectsRotation(t *testing.T) {
	scope := identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}
	bindings := []Binding{{Scope: scope, Group: "team", Role: Investigator}}
	a, _ := NewPolicy(bindings)
	b, _ := NewPolicy(bindings)
	key := bytes.Repeat([]byte{7}, 32)
	if err := a.SetGrantKey(key, "generation-1"); err != nil {
		t.Fatal(err)
	}
	if err := b.SetGrantKey(key, "generation-1"); err != nil {
		t.Fatal(err)
	}
	p := identity.Principal{ID: "user", Issuer: "https://idp", Groups: []string{"team"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	token, err := a.SealPrincipal(p, scope, Investigate)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b.OpenPrincipal(token, scope, Investigate); err != nil || got.ID != p.ID {
		t.Fatal("replica cannot open authority", err)
	}
	if err := b.SetGrantKey(key, "generation-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.OpenPrincipal(token, scope, Investigate); err == nil {
		t.Fatal("generation rotation retained old grant")
	}
	if err := b.SetGrantKey([]byte("short"), "generation-2"); err == nil {
		t.Fatal("accepted short key")
	}
}
