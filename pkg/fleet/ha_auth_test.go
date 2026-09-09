package fleet

import (
	"context"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"testing"
	"time"
)

func TestAuthorityEpochSurvivesReplicaStart(t *testing.T) {
	policy := &authorization.Policy{}
	a, err := NewService(&postgres.Store{}, policy, "generation-1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewService(&postgres.Store{}, policy, "generation-1")
	if err != nil {
		t.Fatal(err)
	}
	if a.Epoch != b.Epoch {
		t.Fatal("replica start changed authority epoch")
	}
	c, err := NewService(&postgres.Store{}, policy, "generation-2")
	if err != nil {
		t.Fatal(err)
	}
	if c.Epoch == a.Epoch {
		t.Fatal("explicit generation change retained old authority")
	}
}

func TestCredentialsSurviveReplicaStartAndRejectRotatedGeneration(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	a, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, err := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "admins", Role: authorization.Administrator}})
	if err != nil {
		t.Fatal(err)
	}
	admin := identity.Principal{ID: "admin", Issuer: "https://idp", Groups: []string{"admins"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	first, err := NewService(a, policy, "generation-one")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := first.Bootstrap(ctx, admin, scope, "agent", "cluster-uid", Collector)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewService(b, policy, "generation-one")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := second.Enroll(ctx, scope, bootstrap.Token, "cluster-uid", Collector)
	if err != nil {
		t.Fatal("replica could not consume bootstrap:", err)
	}
	if _, err = first.Authenticate(ctx, scope, credential.Token, Collector); err != nil {
		t.Fatal("replica could not authenticate credential:", err)
	}
	restarted, err := NewService(a, policy, "generation-one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Authenticate(ctx, scope, credential.Token, Collector); err != nil {
		t.Fatal("restart invalidated credential:", err)
	}
	rotated, err := NewService(b, policy, "generation-two")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rotated.Authenticate(ctx, scope, credential.Token, Collector); err == nil {
		t.Fatal("old generation credential survived explicit rotation")
	}
}
