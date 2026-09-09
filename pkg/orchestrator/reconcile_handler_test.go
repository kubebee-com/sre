package orchestrator

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/execution"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReconcileHandlerRejectsScopeAndMalformedInput(t *testing.T) {
	scope := identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owner", Role: authorization.Owner}, {Scope: scope, Group: "viewer", Role: authorization.Viewer}})
	s := Server{config: Config{Policy: policy}}
	for _, tc := range []struct {
		group, app, body string
		want             int
	}{{"viewer", "app", `{"hash":"value"}`, 403}, {"owner", "other", `{"hash":"value"}`, 403}, {"owner", "app", `{"hash":"value","force":true}`, 400}, {"owner", "app", `{`, 400}} {
		r := httptest.NewRequest(http.MethodPost, "/api/actions/action/reconcile?organization_id=org&cluster_id=cluster&application_id="+tc.app, strings.NewReader(tc.body))
		p := identity.Principal{ID: "engineer", Issuer: "https://idp", Groups: []string{tc.group}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
		w := httptest.NewRecorder()
		s.reconcileAction(w, r)
		if w.Code != tc.want {
			t.Fatalf("got %d want %d", w.Code, tc.want)
		}
	}
}

func TestReconcileAPIRouteExactAction(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, e := postgres.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owner", Role: authorization.Owner}})
	p := identity.Principal{ID: "owner", Issuer: "https://idp", Groups: []string{"owner"}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}
	plan := incident.ActionPlan{Scope: scope, ID: "action", IncidentID: "incident", Kind: "REPLACE_POD"}
	a := incident.Action{Plan: plan, Hash: plan.Hash(), Version: 1, State: "SUBMITTED", SubmittedAt: time.Now().Add(-3 * time.Minute)}
	if e = db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if e := tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()}); e != nil {
			return e
		}
		return tx.SaveAction(a, 0, "")
	}); e != nil {
		t.Fatal(e)
	}
	s, e := New(Config{DB: db, Policy: policy, PublicURL: "https://sre.example", Execution: &execution.Service{Enabled: true, Fleet: &fleet.Service{DB: db, Policy: policy}}, Verifier: verifierFunc(func(context.Context, string) (identity.Principal, error) { return p, nil })})
	if e != nil {
		t.Fatal(e)
	}
	for i, want := range []int{200, 409} {
		r := httptest.NewRequest(http.MethodPost, "/api/actions/action/reconcile?organization_id="+scope.OrganizationID+"&cluster_id=cluster&application_id=app", strings.NewReader(`{"hash":"`+a.Hash+`"}`))
		r.Header.Set("Authorization", "Bearer valid")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("attempt %d got %d: %s", i, w.Code, w.Body.String())
		}
		if i == 0 {
			var out incident.Action
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.State != "AMBIGUOUS" || out.ReconciledBy != "owner" {
				t.Fatal("bad response")
			}
		}
	}
}
