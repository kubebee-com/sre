package identity

import "testing"

func TestScopeRequiresEveryBoundary(t *testing.T) {
	for _, scope := range []Scope{{}, {OrganizationID: "org", ClusterID: "cluster"}, {OrganizationID: "org", ApplicationID: "app"}, {ClusterID: "cluster", ApplicationID: "app"}, {OrganizationID: "org:other", ClusterID: "c", ApplicationID: "a"}} {
		if scope.Validate() == nil {
			t.Fatalf("invalid scope accepted: %#v", scope)
		}
	}
	a := Scope{OrganizationID: "org", ClusterID: "cluster-a", ApplicationID: "app"}
	b := Scope{OrganizationID: "org", ClusterID: "cluster-b", ApplicationID: "app"}
	if a.Validate() != nil || a.Key() == b.Key() {
		t.Fatal("valid cluster isolation failed")
	}
}
