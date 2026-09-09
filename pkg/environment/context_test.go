package environment

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"testing"
)

func TestContextIsTypedAndCannotGrantAnotherTenantAccess(t *testing.T) {
	c := incident.EnvironmentContext{Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, Version: 1, Environment: "PRODUCTION", Platform: "EKS", Topology: "MULTI_ZONE", Criticality: "HIGH"}
	if Validate(c) != nil {
		t.Fatal("valid setup rejected")
	}
	c.Platform = "customer-alice"
	if Validate(c) == nil {
		t.Fatal("customer prose accepted")
	}
	c.Platform = "EKS"
	c.Dependencies = []identity.Scope{{OrganizationID: "other", ClusterID: "c", ApplicationID: "a"}}
	if Validate(c) == nil {
		t.Fatal("cross-tenant dependency accepted")
	}
}
