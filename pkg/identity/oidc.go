package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var ErrUnauthenticated = errors.New("verified engineer identity required")

const MaxIdentityAge = 15 * time.Minute

type Principal struct {
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	Groups    []string  `json:"-"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (p Principal) Valid(at time.Time) bool {
	return ValidID(p.ID) && p.Issuer != "" && !p.IssuedAt.IsZero() && !p.IssuedAt.After(at.Add(30*time.Second)) && at.Before(p.ExpiresAt) && at.Sub(p.IssuedAt) <= MaxIdentityAge
}

type OIDCVerifier struct {
	endpoint         oauth2.Endpoint
	verifier         *oidc.IDTokenVerifier
	issuer, audience string
}

func NewOIDCVerifier(ctx context.Context, issuer, audience string) (*OIDCVerifier, error) {
	return newOIDCVerifier(ctx, issuer, audience, &http.Client{Timeout: 10 * time.Second})
}
func newOIDCVerifier(ctx context.Context, issuer, audience string, client *http.Client) (*OIDCVerifier, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.TrimSpace(audience) == "" {
		return nil, ErrUnauthenticated
	}
	bounded := *client
	bounded.Timeout = 10 * time.Second
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("identity redirects are disabled") }
	// The key cache retains this client context across verifications. Do not bind
	// it to a short-lived discovery timeout context.
	ctx = oidc.ClientContext(ctx, &bounded)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	var metadata struct {
		JWKS string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil {
		return nil, ErrUnauthenticated
	}
	keys, err := url.Parse(metadata.JWKS)
	if err != nil || keys.Scheme != "https" || keys.Host == "" || keys.User != nil || keys.Fragment != "" {
		return nil, ErrUnauthenticated
	}
	return &OIDCVerifier{verifier: provider.Verifier(&oidc.Config{ClientID: audience, SupportedSigningAlgs: []string{"RS256", "ES256"}}), issuer: issuer, audience: audience, endpoint: provider.Endpoint()}, nil
}
func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (Principal, error) {
	if len(raw) == 0 || len(raw) > 16384 {
		return Principal{}, ErrUnauthenticated
	}
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil {
		return Principal{}, ErrUnauthenticated
	}
	var claims struct {
		Groups          []string `json:"groups"`
		AuthorizedParty string   `json:"azp"`
		NotBefore       int64    `json:"nbf"`
	}
	if token.Claims(&claims) != nil || token.Subject == "" || len(token.Subject) > 1024 || len(claims.Groups) > 128 {
		return Principal{}, ErrUnauthenticated
	}
	now := time.Now()
	if claims.NotBefore > now.Unix() || (len(token.Audience) > 1 && claims.AuthorizedParty != v.audience) {
		return Principal{}, ErrUnauthenticated
	}
	for _, group := range claims.Groups {
		if group == "" || len(group) > 256 || strings.ContainsAny(group, "\r\n\x00") {
			return Principal{}, ErrUnauthenticated
		}
	}
	sort.Strings(claims.Groups)
	digest := sha256.Sum256([]byte(v.issuer + "\x00" + token.Subject))
	expiry := token.Expiry
	if ageExpiry := token.IssuedAt.Add(MaxIdentityAge); ageExpiry.Before(expiry) {
		expiry = ageExpiry
	}
	principal := Principal{ID: hex.EncodeToString(digest[:]), Issuer: v.issuer, Groups: append([]string(nil), claims.Groups...), IssuedAt: token.IssuedAt, ExpiresAt: expiry}
	if !principal.Valid(now) {
		return Principal{}, ErrUnauthenticated
	}
	return principal, nil
}

func (v *OIDCVerifier) OAuthEndpoint() oauth2.Endpoint { return v.endpoint }
func (v *OIDCVerifier) VerifyNonce(ctx context.Context, raw, nonce string) (Principal, error) {
	if nonce == "" || len(raw) > 16384 {
		return Principal{}, ErrUnauthenticated
	}
	token, err := v.verifier.Verify(ctx, raw)
	if err != nil || token.Nonce != nonce {
		return Principal{}, ErrUnauthenticated
	}
	return v.Verify(ctx, raw)
}
