package orchestrator

import (
	"context"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/interaction"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestInteractionRequiresScopedHuman(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	db, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "cluster", ApplicationID: "app"}
	policy, _ := authorization.NewPolicy([]authorization.Binding{{Scope: scope, Group: "owners", Role: authorization.Owner}, {Scope: scope, Group: "readers", Role: authorization.Viewer}})
	server, err := New(Config{DB: db, Policy: policy, PublicURL: "https://sre.example", Verifier: verifierFunc(func(_ context.Context, token string) (identity.Principal, error) {
		if token != "owners" && token != "readers" {
			return identity.Principal{}, identity.ErrUnauthenticated
		}
		return identity.Principal{ID: token, Issuer: "https://idp", Groups: []string{token}, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Transact(context.Background(), scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "incident", Version: 1, State: "OPEN", OpenedAt: time.Now()}); err != nil {
			return err
		}
		return tx.CreateInteraction(interaction.Request{Scope: scope, ID: "question", IncidentID: "incident", Kind: interaction.Clarification, Question: "IMPACT", Version: 1, Status: "PENDING", ExpiresAt: time.Now().Add(time.Hour)}, "owners")
	})
	if err != nil {
		t.Fatal(err)
	}
	query := "?organization_id=" + scope.OrganizationID + "&cluster_id=cluster&application_id=app"
	for _, tc := range []struct {
		token, query, body string
		want               int
	}{{"agent", query, `{"version":1,"answer":"UNKNOWN"}`, 401}, {"readers", query, `{"version":1,"answer":"UNKNOWN"}`, 403}, {"owners", query + "other", `{"version":1,"answer":"UNKNOWN"}`, 403}, {"owners", query, `{"version":1,"answer":"yes"}`, 400}, {"owners", query, `{"version":1,"answer":"UNKNOWN"}`, 200}, {"owners", query, `{"version":1,"answer":"UNKNOWN"}`, 409}} {
		r := httptest.NewRequest(http.MethodPost, "/api/interactions/question/answer"+tc.query, strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got %d want %d: %s", tc.token, w.Code, tc.want, w.Body.String())
		}
	}
}

func TestInteractionUIContracts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node required")
	}
	if out, err := exec.Command(node, "static/testdata/interaction.js").CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}
