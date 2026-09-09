package orchestrator

import (
	"context"
	"crypto/subtle"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"golang.org/x/oauth2"
	"net/http"
	"strings"
	"time"
)

type nonceVerifier interface {
	VerifyNonce(context.Context, string, string) (identity.Principal, error)
}
type challenge struct {
	verifier, nonce string
	expires         time.Time
}
type browserSession struct {
	principal identity.Principal
	csrf      string
}
type csrfKey struct{}

func (s *Server) initAuth() {
	s.challenges = map[string]challenge{}
	s.sessions = map[string]browserSession{}
	if s.config.AuthStore == nil {
		if s.config.DB != nil {
			s.config.AuthStore = s.config.DB
		} else {
			s.config.AuthStore = memoryAuthStore{server: s}
		}
	}
}
func (s *Server) pruneAuth(now time.Time) {
	for key, state := range s.challenges {
		if !state.expires.After(now) {
			delete(s.challenges, key)
		}
	}
	for key, session := range s.sessions {
		if !session.principal.Valid(now) {
			delete(s.sessions, key)
		}
	}
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.config.OAuth == nil {
		writeError(w, 503, "company sign-in is not configured")
		return
	}
	state, nonce := identity.NewID(), identity.NewID()
	verifier := oauth2.GenerateVerifier()
	err := s.config.AuthStore.CreateLoginChallenge(r.Context(), state, postgres.LoginChallenge{Verifier: verifier, Nonce: nonce, ExpiresAt: time.Now().Add(5 * time.Minute)})
	if err != nil {
		s.authStoreError(w, err, "sign-in capacity reached")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Secure-sre-login", Value: state, Path: "/auth/callback", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	http.Redirect(w, r, s.config.OAuth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)), http.StatusSeeOther)
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	verifier, ok := s.config.Verifier.(nonceVerifier)
	if s.config.OAuth == nil || !ok {
		writeError(w, 503, "company sign-in unavailable")
		return
	}
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie("__Secure-sre-login")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) != 1 {
		writeError(w, 400, "invalid sign-in state")
		return
	}
	pending, err := s.config.AuthStore.ConsumeLoginChallenge(r.Context(), state)
	if err != nil && !errors.Is(err, postgres.ErrNotFound) {
		s.authStoreError(w, err, "")
		return
	}
	if err != nil || !pending.ExpiresAt.After(time.Now()) || r.URL.Query().Get("code") == "" {
		writeError(w, 400, "expired or consumed sign-in state")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 10 * time.Second}
	if s.config.AuthHTTPClient != nil {
		copy := *s.config.AuthHTTPClient
		client = &copy
	}
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("identity redirects disabled") }
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	token, err := s.config.OAuth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		writeError(w, 401, "sign-in exchange failed")
		return
	}
	raw, _ := token.Extra("id_token").(string)
	principal, err := verifier.VerifyNonce(ctx, raw, pending.Nonce)
	if err != nil {
		writeError(w, 401, "identity verification failed")
		return
	}
	sessionID := identity.NewID()
	if err := s.config.AuthStore.CreateBrowserSession(r.Context(), sessionID, postgres.BrowserSession{Principal: principal, CSRF: identity.NewID()}); err != nil {
		s.authStoreError(w, err, "session capacity reached")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Secure-sre-login", Path: "/auth/callback", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "__Host-sre-session", Value: sessionID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(time.Until(principal.ExpiresAt).Seconds())})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (s *Server) authenticate(r *http.Request) (identity.Principal, string, error) {
	values := r.Header.Values("Authorization")
	if len(values) > 0 {
		if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
			return identity.Principal{}, "", identity.ErrUnauthenticated
		}
		p, err := s.config.Verifier.Verify(r.Context(), strings.TrimPrefix(values[0], "Bearer "))
		return p, "", err
	}
	cookie, err := r.Cookie("__Host-sre-session")
	if err != nil {
		return identity.Principal{}, "", identity.ErrUnauthenticated
	}
	session, err := s.config.AuthStore.BrowserSession(r.Context(), cookie.Value)
	if err != nil || !session.Principal.Valid(time.Now()) {
		return identity.Principal{}, "", identity.ErrUnauthenticated
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Header.Get("Origin") != strings.TrimRight(s.config.PublicURL, "/") || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-SRE-CSRF")), []byte(session.CSRF)) != 1 {
			return identity.Principal{}, "", identity.ErrUnauthenticated
		}
	}
	return session.Principal, session.CSRF, nil
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("__Host-sre-session"); err == nil {
		if err := s.config.AuthStore.DeleteBrowserSession(r.Context(), cookie.Value); err != nil {
			s.authStoreError(w, err, "")
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sre-session", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"signed_out": true})
}

func (s *Server) authStoreError(w http.ResponseWriter, err error, capacityMessage string) {
	if errors.Is(err, postgres.ErrAuthCapacity) {
		writeError(w, 429, capacityMessage)
		return
	}
	writeError(w, 503, "authentication storage unavailable")
}
