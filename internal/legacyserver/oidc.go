package legacyserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/identity"
	"golang.org/x/oauth2"
)

type OIDCConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	PublicURL     string
	Scopes        []string
	AllowedGroups []string
}

type loginChallenge struct {
	verifier string
	nonce    string
	expires  time.Time
}

type browserSession struct {
	principal identity.Principal
	expires   time.Time
}

type oidcAuthenticator struct {
	issuer        string
	clientID      string
	clientSecret  string
	publicURL     string
	scopes        []string
	allowedGroups map[string]struct{}

	mu         sync.RWMutex
	verifier   *identity.OIDCVerifier
	oauthCfg   *oauth2.Config
	challenges map[string]loginChallenge
	sessions   map[string]browserSession
}

func newOIDCAuthenticator(ctx context.Context, cfg OIDCConfig) (*oidcAuthenticator, error) {
	issuer := strings.TrimSpace(cfg.Issuer)
	clientID := strings.TrimSpace(cfg.ClientID)
	if issuer == "" || clientID == "" {
		return nil, errors.New("oidc issuer and client_id are required")
	}

	allowedGroups := make(map[string]struct{}, len(cfg.AllowedGroups))
	for _, g := range cfg.AllowedGroups {
		g = strings.TrimSpace(g)
		if g != "" {
			allowedGroups[g] = struct{}{}
		}
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	auth := &oidcAuthenticator{
		issuer:        issuer,
		clientID:      clientID,
		clientSecret:  strings.TrimSpace(cfg.ClientSecret),
		publicURL:     strings.TrimRight(cfg.PublicURL, "/"),
		scopes:        scopes,
		allowedGroups: allowedGroups,
		challenges:    make(map[string]loginChallenge),
		sessions:      make(map[string]browserSession),
	}

	_ = auth.ensureVerifier(ctx)
	return auth, nil
}

func (a *oidcAuthenticator) ensureVerifier(ctx context.Context) error {
	a.mu.RLock()
	if a.verifier != nil && a.oauthCfg != nil {
		a.mu.RUnlock()
		return nil
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.verifier != nil && a.oauthCfg != nil {
		return nil
	}

	if ctx == nil {
		ctx = context.Background()
	}
	discoCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	v, err := identity.NewOIDCVerifier(discoCtx, a.issuer, a.clientID)
	if err != nil {
		return fmt.Errorf("oidc discovery failed: %w", err)
	}

	redirectURL := a.publicURL + "/auth/callback"
	oauthCfg := &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     v.OAuthEndpoint(),
		RedirectURL:  redirectURL,
		Scopes:       append([]string(nil), a.scopes...),
	}

	a.verifier = v
	a.oauthCfg = oauthCfg
	return nil
}

func (a *oidcAuthenticator) prune(now time.Time) {
	for k, c := range a.challenges {
		if now.After(c.expires) {
			delete(a.challenges, k)
		}
	}
	for k, s := range a.sessions {
		if now.After(s.expires) || !s.principal.Valid(now) {
			delete(a.sessions, k)
		}
	}
}

func (a *oidcAuthenticator) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := a.ensureVerifier(r.Context()); err != nil {
		http.Error(w, "SSO identity provider unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	a.mu.Lock()
	a.prune(time.Now())

	state := identity.NewID()
	nonce := identity.NewID()
	codeVerifier := oauth2.GenerateVerifier()

	a.challenges[state] = loginChallenge{
		verifier: codeVerifier,
		nonce:    nonce,
		expires:  time.Now().Add(10 * time.Minute),
	}
	oauthCfg := a.oauthCfg
	a.mu.Unlock()

	isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || strings.HasPrefix(a.publicURL, "https://")
	http.SetCookie(w, &http.Cookie{
		Name:     "sre-login-state",
		Value:    state,
		Path:     "/auth/callback",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})

	authURL := oauthCfg.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(codeVerifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func (a *oidcAuthenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	if err := a.ensureVerifier(r.Context()); err != nil {
		http.Error(w, "SSO identity provider unavailable", http.StatusServiceUnavailable)
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state or authorization code", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie("sre-login-state")
	if err != nil || subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie.Value)) != 1 {
		http.Error(w, "invalid or mismatched sign-in state", http.StatusBadRequest)
		return
	}

	a.mu.Lock()
	challenge, found := a.challenges[state]
	if found {
		delete(a.challenges, state)
	}
	oauthCfg := a.oauthCfg
	verifier := a.verifier
	a.mu.Unlock()

	if !found || time.Now().After(challenge.expires) {
		http.Error(w, "expired or already consumed sign-in state", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	token, err := oauthCfg.Exchange(ctx, code, oauth2.VerifierOption(challenge.verifier))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "missing id_token in token response", http.StatusUnauthorized)
		return
	}

	principal, err := verifier.VerifyNonce(ctx, rawIDToken, challenge.nonce)
	if err != nil {
		http.Error(w, "identity verification failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if len(a.allowedGroups) > 0 {
		authorized := false
		for _, g := range principal.Groups {
			if _, ok := a.allowedGroups[g]; ok {
				authorized = true
				break
			}
		}
		if !authorized {
			http.Error(w, "forbidden: user not in an authorized group", http.StatusForbidden)
			return
		}
	}

	sessionID := identity.NewID()
	expires := principal.ExpiresAt
	if expires.IsZero() || time.Until(expires) > 24*time.Hour {
		expires = time.Now().Add(24 * time.Hour)
	}

	a.mu.Lock()
	a.sessions[sessionID] = browserSession{
		principal: principal,
		expires:   expires,
	}
	a.mu.Unlock()

	isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || strings.HasPrefix(a.publicURL, "https://")

	http.SetCookie(w, &http.Cookie{
		Name:     "sre-login-state",
		Path:     "/auth/callback",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	maxAge := int(time.Until(expires).Seconds())
	if maxAge <= 0 {
		maxAge = 900
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sre-session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *oidcAuthenticator) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("sre-session"); err == nil && cookie.Value != "" {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}

	isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || strings.HasPrefix(a.publicURL, "https://")
	http.SetCookie(w, &http.Cookie{
		Name:     "sre-session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	if r.URL.Path == "/api/auth/logout" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"signed_out": true})
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *oidcAuthenticator) authenticateSession(r *http.Request) (identity.Principal, bool) {
	cookie, err := r.Cookie("sre-session")
	if err != nil || cookie.Value == "" {
		return identity.Principal{}, false
	}

	a.mu.RLock()
	session, ok := a.sessions[cookie.Value]
	a.mu.RUnlock()

	if !ok {
		return identity.Principal{}, false
	}

	now := time.Now()
	if now.After(session.expires) || !session.principal.Valid(now) {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
		return identity.Principal{}, false
	}

	return session.principal, true
}

func (a *oidcAuthenticator) verifyBearerToken(ctx context.Context, raw string) (identity.Principal, error) {
	if err := a.ensureVerifier(ctx); err != nil {
		return identity.Principal{}, err
	}
	a.mu.RLock()
	verifier := a.verifier
	a.mu.RUnlock()
	if verifier == nil {
		return identity.Principal{}, errors.New("oidc verifier unavailable")
	}

	p, err := verifier.Verify(ctx, raw)
	if err != nil {
		return identity.Principal{}, err
	}
	if len(a.allowedGroups) > 0 {
		authorized := false
		for _, g := range p.Groups {
			if _, ok := a.allowedGroups[g]; ok {
				authorized = true
				break
			}
		}
		if !authorized {
			return identity.Principal{}, errors.New("principal not in authorized group")
		}
	}
	return p, nil
}
