package interaction

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTerminalExactApprovalAndEOF(t *testing.T) {
	for _, tc := range []struct {
		input    string
		approved bool
	}{{"yes\n", false}, {"approve action wrong\n", false}, {"approve action exact\n", true}, {"", false}} {
		t.Run(tc.input, func(t *testing.T) {
			count := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer human" {
					t.Error("human identity missing")
				}
				if r.Method == "POST" {
					count++
					var v map[string]string
					json.NewDecoder(r.Body).Decode(&v)
					if r.URL.Path != "/api/actions/action/approve" || v["hash"] != "exact" {
						t.Error("wrong authority/payload")
					}
					io.WriteString(w, "{}")
					return
				}
				if r.URL.Path == "/api/actions" {
					json.NewEncoder(w).Encode([]incident.Action{{Plan: incident.ActionPlan{ID: "action", ExpiresAt: time.Now().Add(time.Hour)}, State: "PROPOSED", Hash: "exact"}})
				} else {
					io.WriteString(w, "[]")
				}
			}))
			defer s.Close()
			var out bytes.Buffer
			err := Run(context.Background(), ClientConfig{BaseURL: s.URL, HumanToken: "human", Scope: identity.Scope{OrganizationID: "org", ClusterID: "cluster", ApplicationID: "app"}, Input: strings.NewReader(tc.input), Output: &out, HTTPClient: s.Client()})
			if err != nil {
				t.Fatal(err)
			}
			if (count == 1) != tc.approved {
				t.Fatalf("posts=%d", count)
			}
		})
	}
}
func TestTerminalRequiresSeparateHumanCredential(t *testing.T) {
	if Run(context.Background(), ClientConfig{BaseURL: "https://example.com", Input: strings.NewReader(""), Output: io.Discard}) == nil {
		t.Fatal("missing human accepted")
	}
}

func TestTerminalDispatchesDiagnosisThroughOrchestrator(t *testing.T) {
	posts := 0
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["profile_id"] != "approved" || r.URL.Path != "/api/incidents/incident/investigate" || r.Header.Get("Authorization") != "Bearer human" {
				t.Error("wrong diagnosis authority")
			}
			posts++
			w.WriteHeader(202)
			io.WriteString(w, "{}")
			return
		}
		io.WriteString(w, "[]")
	}))
	defer s.Close()
	err := Run(context.Background(), ClientConfig{BaseURL: s.URL, HumanToken: "human", Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, Input: strings.NewReader("investigate incident approved\n"), Output: io.Discard, HTTPClient: s.Client()})
	if err != nil || posts != 1 {
		t.Fatalf("diagnosis was not dispatched: posts=%d err=%v", posts, err)
	}
}
