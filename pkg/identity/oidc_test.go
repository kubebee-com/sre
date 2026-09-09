package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOIDCValidatesAuthorityAndTime(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "alg": "RS256", "kid": "test", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	issuer = server.URL
	verifier, err := newOIDCVerifier(context.Background(), issuer, "sre", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(jwt.MapClaims){"valid": func(jwt.MapClaims) {}, "issuer": func(c jwt.MapClaims) { c["iss"] = "https://other" }, "audience": func(c jwt.MapClaims) { c["aud"] = "other" }, "expired": func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, "old": func(c jwt.MapClaims) { c["iat"] = time.Now().Add(-time.Hour).Unix() }, "future": func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }, "subject": func(c jwt.MapClaims) { delete(c, "sub") }, "issued": func(c jwt.MapClaims) { delete(c, "iat") }, "authorized-party": func(c jwt.MapClaims) { c["aud"] = []string{"sre", "other"}; c["azp"] = "other" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": issuer, "aud": "sre", "sub": "real-subject", "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(), "groups": []string{"team-a"}}
			mutate(claims)
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			token.Header["kid"] = "test"
			signed, err := token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			principal, err := verifier.Verify(context.Background(), signed)
			if name == "valid" {
				if err != nil || principal.ID == "real-subject" || len(principal.Groups) != 1 {
					t.Fatalf("valid principal: %#v %v", principal, err)
				}
			} else if err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
	if _, err := NewOIDCVerifier(context.Background(), "http://idp.example", "sre"); err == nil {
		t.Fatal("HTTP issuer accepted")
	}
}
