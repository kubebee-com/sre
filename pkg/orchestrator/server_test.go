package orchestrator

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type verifierFunc func(context.Context, string) (identity.Principal, error)

func (f verifierFunc) Verify(ctx context.Context, token string) (identity.Principal, error) {
	return f(ctx, token)
}
func TestAPIDeniesCrossScopeAndLegacyMutations(t *testing.T) {
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
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "team", Role: authorization.Owner}})
	principal := identity.Principal{ID: "engineer", Issuer: "https://idp", Groups: []string{"team"}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Minute)}
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		return tx.CreateIncident(incident.Incident{Scope: scope, ID: "one", Version: 1, State: "OPEN", OpenedAt: time.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{DB: db, Policy: policy, Verifier: verifierFunc(func(_ context.Context, token string) (identity.Principal, error) {
		if token != "valid" {
			return identity.Principal{}, identity.ErrUnauthenticated
		}
		return principal, nil
	}), PublicURL: "https://sre.example"})
	if err != nil {
		t.Fatal(err)
	}
	query := "?organization_id=" + scope.OrganizationID + "&cluster_id=cluster&application_id=app"
	for _, tc := range []struct {
		path, token string
		want        int
	}{{"/api/incidents" + query, "valid", 200}, {"/api/incidents" + query, "", 401}, {"/api/incidents?organization_id=" + scope.OrganizationID + "&cluster_id=other&application_id=app", "valid", 403}, {"/api/clean/pods" + query, "valid", 404}, {"/api/proposals" + query, "valid", 404}} {
		request := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.token != "" {
			request.Header.Set("Authorization", "Bearer "+tc.token)
		}
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != tc.want {
			t.Fatalf("%s: %d %s", tc.path, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/incidents"+query, nil)
	request.Header.Set("Authorization", "Bearer valid")
	request.Header.Set("X-User-Email", "owner@example.com")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != 400 {
		t.Fatal("asserted actor header accepted")
	}
	request = httptest.NewRequest(http.MethodGet, "/api/scopes", nil)
	request.Header.Set("Authorization", "Bearer valid")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	var scopes []identity.Scope
	if json.Unmarshal(response.Body.Bytes(), &scopes) != nil || len(scopes) != 1 {
		t.Fatal("scope selector failed")
	}
}
