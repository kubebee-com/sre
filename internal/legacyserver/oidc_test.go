package legacyserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/identity"
)

func TestOIDCAuthenticatorSessionLifecycle(t *testing.T) {
	auth := &oidcAuthenticator{
		issuer:     "https://sso.example.com/realms/infra",
		clientID:   "sre",
		publicURL:  "https://sre.infra.kubeb.com",
		challenges: make(map[string]loginChallenge),
		sessions:   make(map[string]browserSession),
	}

	sessionID := identity.NewID()
	principal := identity.Principal{
		ID:                identity.NewID(),
		Issuer:            auth.issuer,
		Email:             "sre-admin@kubeb.com",
		PreferredUsername: "sre-admin",
		Name:              "SRE Administrator",
		IssuedAt:          time.Now(),
		ExpiresAt:         time.Now().Add(10 * time.Minute),
	}

	auth.sessions[sessionID] = browserSession{
		principal: principal,
		expires:   principal.ExpiresAt,
	}

	req := httptest.NewRequest(http.MethodGet, "https://sre.infra.kubeb.com/api/status", nil)
	req.AddCookie(&http.Cookie{
		Name:  "sre-session",
		Value: sessionID,
	})

	gotPrincipal, ok := auth.authenticateSession(req)
	if !ok {
		t.Fatalf("expected authenticateSession to succeed")
	}
	if gotPrincipal.Email != "sre-admin@kubeb.com" {
		t.Errorf("got email %q, expected sre-admin@kubeb.com", gotPrincipal.Email)
	}

	// Test logout clears session
	w := httptest.NewRecorder()
	auth.handleLogout(w, req)
	if _, ok := auth.sessions[sessionID]; ok {
		t.Errorf("expected session %s to be deleted after logout", sessionID)
	}

	cookies := w.Result().Cookies()
	var clearedCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "sre-session" {
			clearedCookie = c
			break
		}
	}
	if clearedCookie == nil || clearedCookie.MaxAge >= 0 {
		t.Errorf("expected sre-session cookie to be cleared (MaxAge < 0)")
	}
}

func TestServerOIDCAuthenticateRequest(t *testing.T) {
	auth := &oidcAuthenticator{
		issuer:     "https://sso.example.com/realms/infra",
		clientID:   "sre",
		publicURL:  "https://sre.infra.kubeb.com",
		challenges: make(map[string]loginChallenge),
		sessions:   make(map[string]browserSession),
	}

	srv := &Server{
		authenticator: newTokenAuthenticator("static-secret-token"),
		oidcAuth:      auth,
	}

	// 1. Session Cookie Auth
	sessionID := identity.NewID()
	auth.sessions[sessionID] = browserSession{
		principal: identity.Principal{
			ID:                identity.NewID(),
			Issuer:            auth.issuer,
			Email:             "alice@kubeb.com",
			IssuedAt:          time.Now(),
			ExpiresAt:         time.Now().Add(10 * time.Minute),
		},
		expires: time.Now().Add(10 * time.Minute),
	}

	sessionReq := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	sessionReq.AddCookie(&http.Cookie{Name: "sre-session", Value: sessionID})
	actor, ok := srv.authenticateRequest(sessionReq)
	if !ok || actor != "alice@kubeb.com" {
		t.Fatalf("expected session auth as alice@kubeb.com, got %s (ok=%v)", actor, ok)
	}

	// 2. Static Bearer Token Auth (break-glass fallback)
	tokenReq := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	tokenReq.Header.Set("Authorization", "Bearer static-secret-token")
	actor, ok = srv.authenticateRequest(tokenReq)
	if !ok || actor != "api-token" {
		t.Fatalf("expected static token auth as api-token, got %s (ok=%v)", actor, ok)
	}

	// 3. Unauthenticated request
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/issues", nil)
	actor, ok = srv.authenticateRequest(unauthReq)
	if ok {
		t.Fatalf("expected unauthenticated request to fail, got actor=%s", actor)
	}
}

func TestServerAuthConfigAndMe(t *testing.T) {
	auth := &oidcAuthenticator{
		issuer:     "https://sso.example.com/realms/infra",
		clientID:   "sre",
		publicURL:  "https://sre.infra.kubeb.com",
		challenges: make(map[string]loginChallenge),
		sessions:   make(map[string]browserSession),
	}

	srv := &Server{
		authenticator:   newTokenAuthenticator("secret"),
		oidcAuth:        auth,
		requireAPIToken: true,
	}

	// Test /api/auth/config
	cfgReq := httptest.NewRequest(http.MethodGet, "/api/auth/config", nil)
	cfgRec := httptest.NewRecorder()
	srv.handleAuthConfig(cfgRec, cfgReq)

	if cfgRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/auth/config, got %d", cfgRec.Code)
	}
	var configResp map[string]interface{}
	if err := json.Unmarshal(cfgRec.Body.Bytes(), &configResp); err != nil {
		t.Fatalf("failed to parse /api/auth/config JSON: %v", err)
	}
	if configResp["oidc_enabled"] != true {
		t.Errorf("expected oidc_enabled=true")
	}

	// Test /api/auth/me unauthenticated
	meReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meRec := httptest.NewRecorder()
	srv.handleAuthMe(meRec, meReq)

	var meResp map[string]interface{}
	if err := json.Unmarshal(meRec.Body.Bytes(), &meResp); err != nil {
		t.Fatalf("failed to parse /api/auth/me JSON: %v", err)
	}
	if meResp["authenticated"] != false {
		t.Errorf("expected authenticated=false for anonymous caller")
	}

	// Test /api/auth/me authenticated with session
	sessionID := identity.NewID()
	auth.sessions[sessionID] = browserSession{
		principal: identity.Principal{
			ID:                identity.NewID(),
			Issuer:            auth.issuer,
			Email:             "bob@kubeb.com",
			PreferredUsername: "bob",
			Name:              "Bob Builder",
			IssuedAt:          time.Now(),
			ExpiresAt:         time.Now().Add(10 * time.Minute),
		},
		expires: time.Now().Add(10 * time.Minute),
	}
	meAuthReq := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	meAuthReq.AddCookie(&http.Cookie{Name: "sre-session", Value: sessionID})
	meAuthRec := httptest.NewRecorder()
	srv.handleAuthMe(meAuthRec, meAuthReq)

	var meAuthResp map[string]interface{}
	if err := json.Unmarshal(meAuthRec.Body.Bytes(), &meAuthResp); err != nil {
		t.Fatalf("failed to parse authenticated /api/auth/me JSON: %v", err)
	}
	if meAuthResp["authenticated"] != true || meAuthResp["email"] != "bob@kubeb.com" || meAuthResp["auth_type"] != "oidc" {
		t.Errorf("unexpected /api/auth/me response: %+v", meAuthResp)
	}
}

func TestOIDCCallbackURLResolution(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		reqHost   string
		reqHeader map[string]string
		want      string
	}{
		{
			name:      "Explicit publicURL configured",
			publicURL: "https://sre.infra.kubeb.com",
			reqHost:   "internal.host:8080",
			want:      "https://sre.infra.kubeb.com/auth/callback",
		},
		{
			name:      "Unexpanded template variable falls back to host header",
			publicURL: "https://${cluster__apps__sre__domain:=sre.infra.kubeb.com}",
			reqHost:   "sre.infra.kubeb.com",
			reqHeader: map[string]string{"X-Forwarded-Proto": "https"},
			want:      "https://sre.infra.kubeb.com/auth/callback",
		},
		{
			name:      "Empty publicURL uses forwarded host and proto",
			publicURL: "",
			reqHost:   "10.42.0.200:8080",
			reqHeader: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "sre.infra.kubeb.com",
			},
			want: "https://sre.infra.kubeb.com/auth/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &oidcAuthenticator{publicURL: tt.publicURL}
			req := httptest.NewRequest(http.MethodGet, "http://"+tt.reqHost+"/auth/login", nil)
			req.Host = tt.reqHost
			for k, v := range tt.reqHeader {
				req.Header.Set(k, v)
			}
			got := auth.callbackURL(req)
			if got != tt.want {
				t.Errorf("callbackURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
