package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

func TestBrowserAuthAcrossReplicas(t *testing.T) {
	var exchanges atomic.Int32
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token","token_type":"Bearer","id_token":"id-token"}`))
	}))
	defer tokenServer.Close()
	shared := &Server{}
	shared.initAuth()
	config := Config{PublicURL: "https://sre.example", Verifier: loginVerifier{}, AuthStore: shared.config.AuthStore, AuthHTTPClient: tokenServer.Client(), OAuth: &oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://idp/authorize", TokenURL: tokenServer.URL}}}
	a, b := &Server{config: config}, &Server{config: config}
	a.initAuth()
	b.initAuth()
	login := httptest.NewRecorder()
	a.login(login, httptest.NewRequest("GET", "https://sre.example/auth/login", nil))
	u, _ := url.Parse(login.Header().Get("Location"))
	loginCookie := login.Result().Cookies()[0]
	callback := func(s *Server) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "https://sre.example/auth/callback?code=code&state="+u.Query().Get("state"), nil)
		req.AddCookie(loginCookie)
		res := httptest.NewRecorder()
		s.callback(res, req)
		return res
	}
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); responses <- callback(b) }()
	}
	wg.Wait()
	close(responses)
	var cookie *http.Cookie
	for res := range responses {
		if res.Code == 303 {
			for _, c := range res.Result().Cookies() {
				if c.Name == "__Host-sre-session" {
					cookie = c
				}
			}
		} else if res.Code != 400 {
			t.Fatalf("callback: %d %s", res.Code, res.Body.String())
		}
	}
	if exchanges.Load() != 1 || cookie == nil {
		t.Fatalf("exchanges=%d session=%v", exchanges.Load(), cookie)
	}
	req := httptest.NewRequest("GET", "https://sre.example/api/me", nil)
	req.AddCookie(cookie)
	_, csrf, err := a.authenticate(req)
	if err != nil {
		t.Fatal("other replica cannot authenticate:", err)
	}
	logout := httptest.NewRequest("POST", "https://sre.example/api/logout", nil)
	logout.AddCookie(cookie)
	logout.Header.Set("Origin", config.PublicURL)
	logout.Header.Set("X-SRE-CSRF", csrf)
	if _, _, err := b.authenticate(logout); err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	b.logout(out, logout)
	if _, _, err := a.authenticate(req); err == nil {
		t.Fatal("logout not visible to other replica")
	}
	if _, err := config.AuthStore.ConsumeLoginChallenge(context.Background(), u.Query().Get("state")); err == nil {
		t.Fatal("consumed challenge remained")
	}
}
