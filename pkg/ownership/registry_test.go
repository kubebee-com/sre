package ownership

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"testing"
)

func TestRegistryRejectsConflictsAndCopiesBindings(t *testing.T) {
	app := Application{Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, OwnerGroup: "owner", ApproverGroups: []string{"oncall"}}
	if _, err := NewRegistry([]Application{app, app}); err == nil {
		t.Fatal("conflicting ownership accepted")
	}
	r, err := NewRegistry([]Application{app})
	if err != nil {
		t.Fatal(err)
	}
	app.ApproverGroups[0] = "attacker"
	got, ok := r.Application(app.Scope)
	if !ok || got.ApproverGroups[0] != "oncall" {
		t.Fatal("input aliases registry")
	}
	got.ApproverGroups[0] = "attacker"
	again, _ := r.Application(app.Scope)
	if again.ApproverGroups[0] != "oncall" {
		t.Fatal("read aliases registry")
	}
}
