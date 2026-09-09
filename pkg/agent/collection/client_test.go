package collection

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/fleet"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var runtimeScope = identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}

func testCredential() fleet.Credential {
	return fleet.Credential{Token: strings.Repeat("a", 43), Agent: incident.Agent{Scope: runtimeScope, ID: "collector", Role: fleet.Collector, Audience: "sre-evidence", Epoch: "epoch", Generation: 1, ClusterUID: "cluster-uid", ExpiresAt: time.Now().Add(30 * time.Minute)}}
}
func TestClientRoleBoundExchangeAndPrivateCredential(t *testing.T) {
	calls := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Query().Get("organization_id") != "org" {
			t.Error("missing scope")
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["role"] != fleet.Collector {
			t.Error("role missing")
		}
		if r.URL.Path == "/agent/enroll" {
			if body["cluster_uid"] != "cluster-uid" || body["token"] != strings.Repeat("b", 43) {
				t.Error("invalid enrollment")
			}
		} else if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 43) {
			t.Error("missing bearer")
		}
		json.NewEncoder(w).Encode(testCredential())
	}))
	defer s.Close()
	c, err := newControlClient(s.URL, runtimeScope, s.Client())
	if err != nil {
		t.Fatal(err)
	}
	cred, err := c.enroll(context.Background(), strings.Repeat("b", 43), "cluster-uid")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.renew(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "credential.json")
	if err = saveCredential(path, cred); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("credential public")
	}
	got, err := loadCredential(path)
	if err != nil || got.Token != cred.Token {
		t.Fatal("credential roundtrip")
	}
	os.Chmod(path, 0644)
	if _, err = loadCredential(path); err == nil {
		t.Fatal("public credential accepted")
	}
}
func TestClientRejectsUnsafeOriginRedirectAndOversizedResponse(t *testing.T) {
	for _, origin := range []string{"http://localhost", "https://example.com/path", "https://user@example.com", "https://example.com?x=1"} {
		if _, err := newControlClient(origin, runtimeScope, nil); err == nil {
			t.Fatal("unsafe origin accepted")
		}
	}
	for _, status := range []int{302, 401, 200} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://example.com/private")
				w.WriteHeader(status)
				w.Write([]byte(strings.Repeat("private-canary", 7000)))
			}))
			defer s.Close()
			c, _ := newControlClient(s.URL, runtimeScope, s.Client())
			_, err := c.enroll(context.Background(), strings.Repeat("b", 43), "cluster-uid")
			if err == nil || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("unsafe response accepted")
			}
		})
	}
}
