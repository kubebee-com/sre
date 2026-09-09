package fleet

import (
	"context"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnrollmentIsSingleUseScopedAndRoleBound(t *testing.T) {
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
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "admins", Role: authorization.Administrator}})
	admin := identity.Principal{ID: "admin", Issuer: "https://idp", Groups: []string{"admins"}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	service, err := NewService(db, policy, "external-generation")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := service.Bootstrap(ctx, admin, scope, "collector", "cluster-uid", Collector)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var lock sync.Mutex
	var credential Credential
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := service.Enroll(ctx, scope, bootstrap.Token, "cluster-uid", Collector)
			if err == nil {
				wins.Add(1)
				lock.Lock()
				credential = got
				lock.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("bootstrap consumed %d times", wins.Load())
	}
	if _, err := service.Authenticate(ctx, scope, credential.Token, Executor); err == nil {
		t.Fatal("collector impersonates executor")
	}
	other := scope
	other.ClusterID = "other"
	if _, err := service.Authenticate(ctx, other, credential.Token, Collector); err == nil {
		t.Fatal("cross-cluster token")
	}
	if _, err := service.Authenticate(ctx, scope, credential.Token, Collector); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(ctx, admin, scope, "collector"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, scope, credential.Token, Collector); err == nil {
		t.Fatal("revoked token accepted")
	}
	restored, _ := NewService(db, policy, "rotated-external-generation")
	if restored.Epoch == service.Epoch {
		t.Fatal("explicit generation rotation reused old epoch")
	}
}
