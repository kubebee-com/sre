package authorization

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"testing"
	"time"
)

func TestPolicyIsScopedAndDenyByDefault(t *testing.T) {
	scope := identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}
	principal := identity.Principal{ID: "engineer", Issuer: "https://idp.example", Groups: []string{"team-a"}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)}
	matrix := map[Role][]Permission{Viewer: {Read}, Investigator: {Read, Investigate, Feedback}, Owner: {Read, Investigate, Feedback, Approve}, Approver: {Read, Approve}, Steward: {Read, Feedback, Adjudicate, ReviewKnowledge}, Administrator: {Setup}, SecurityAdministrator: {SecurityPolicy}}
	all := []Permission{Read, Investigate, Feedback, Approve, Adjudicate, ReviewKnowledge, Setup, SecurityPolicy, "shell", "delete"}
	for role, allowed := range matrix {
		p, err := NewPolicy([]Binding{{Scope: scope, Group: "team-a", Role: role}})
		if err != nil {
			t.Fatal(err)
		}
		for _, op := range all {
			want := false
			for _, a := range allowed {
				if a == op {
					want = true
				}
			}
			if got := p.Authorize(principal, scope, op) == nil; got != want {
				t.Errorf("%s/%s allowed=%v", role, op, got)
			}
		}
		other := scope
		other.ClusterID = "other"
		if p.Authorize(principal, other, Read) == nil {
			t.Fatal("cross-cluster access")
		}
	}
}
func TestPolicyVersionAndPrincipalExpiry(t *testing.T) {
	scope := identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}
	a := Binding{Scope: scope, Group: "a", Role: Viewer}
	b := Binding{Scope: scope, Group: "b", Role: Owner}
	p, _ := NewPolicy([]Binding{a, b})
	q, _ := NewPolicy([]Binding{b, a})
	if p.Version() != q.Version() {
		t.Fatal("binding order changed policy version")
	}
	expired := identity.Principal{ID: "engineer", Groups: []string{"b"}, ExpiresAt: time.Now().Add(-time.Second)}
	if p.Authorize(expired, scope, Read) == nil {
		t.Fatal("expired principal accepted")
	}
	if _, err := NewPolicy([]Binding{{Scope: scope, Group: "a", Role: "admin-from-prompt"}}); err == nil {
		t.Fatal("unknown role accepted")
	}
}
