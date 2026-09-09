package orchestrator

import (
	"context"
	"github.com/kubebee-com/sre/pkg/identity"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type loginVerifier struct{}

func (loginVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return identity.Principal{}, identity.ErrUnauthenticated
}
func (loginVerifier) VerifyNonce(_ context.Context, _, nonce string) (identity.Principal, error) {
	if nonce == "" {
		return identity.Principal{}, identity.ErrUnauthenticated
	}
	return identity.Principal{ID: "engineer", Issuer: "https://idp", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func TestLoginBindsStateAndUsesSecureSession(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("code_verifier") == "" {
			t.Error("PKCE verifier missing")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"test","token_type":"Bearer","id_token":"test-id-token"}`))
	}))
	defer tokenServer.Close()
	s := &Server{config: Config{PublicURL: "https://sre.example", Verifier: loginVerifier{}, OAuth: &oauth2.Config{ClientID: "client", RedirectURL: "https://sre.example/auth/callback", Endpoint: oauth2.Endpoint{AuthURL: "https://idp/authorize", TokenURL: tokenServer.URL}, Scopes: []string{"openid"}}, AuthHTTPClient: tokenServer.Client()}}
	s.initAuth()
	response := httptest.NewRecorder()
	s.login(response, httptest.NewRequest("GET", "https://sre.example/auth/login", nil))
	location, _ := url.Parse(response.Header().Get("Location"))
	state := location.Query().Get("state")
	if state == "" || location.Query().Get("nonce") == "" || location.Query().Get("code_challenge") == "" {
		t.Fatal("login lacks state, nonce or PKCE")
	}
	callback := httptest.NewRequest("GET", "https://sre.example/auth/callback?state="+state+"&code=code", nil)
	response = httptest.NewRecorder()
	s.callback(response, callback)
	if response.Code != 400 {
		t.Fatal("unbound login accepted")
	}
	// Begin again because an unbound callback must not authorize a session.
	response = httptest.NewRecorder()
	s.login(response, httptest.NewRequest("GET", "https://sre.example/auth/login", nil))
	location, _ = url.Parse(response.Header().Get("Location"))
	state = location.Query().Get("state")
	cookies := response.Result().Cookies()
	callback = httptest.NewRequest("GET", "https://sre.example/auth/callback?state="+state+"&code=code", nil)
	callback.AddCookie(cookies[0])
	response = httptest.NewRecorder()
	s.callback(response, callback)
	if response.Code != 303 {
		t.Fatalf("callback %d %s", response.Code, response.Body.String())
	}
	found := false
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == "__Host-sre-session" {
			found = true
			if !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("session cookie is not protected")
			}
		}
	}
	if !found {
		t.Fatal("session missing")
	}
	response = httptest.NewRecorder()
	s.callback(response, callback)
	if response.Code != 400 {
		t.Fatal("callback replay accepted")
	}
}

func TestBrowserWritesRequireOriginAndCSRF(t *testing.T) {
	s := &Server{config: Config{PublicURL: "https://sre.example", Verifier: loginVerifier{}}}
	s.initAuth()
	s.sessions["session"] = browserSession{principal: identity.Principal{ID: "engineer", Issuer: "https://idp", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}, csrf: "anti-forgery"}
	request := httptest.NewRequest("POST", "https://sre.example/api/incidents", nil)
	request.AddCookie(&http.Cookie{Name: "__Host-sre-session", Value: "session"})
	if _, _, err := s.authenticate(request); err == nil {
		t.Fatal("cookie write without CSRF accepted")
	}
	request.Header.Set("Origin", "https://sre.example")
	request.Header.Set("X-SRE-CSRF", "anti-forgery")
	if _, _, err := s.authenticate(request); err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "https://attacker.example")
	if _, _, err := s.authenticate(request); err == nil {
		t.Fatal("cross-origin cookie write accepted")
	}
}
