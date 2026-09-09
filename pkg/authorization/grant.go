package authorization

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
)

type queuedPrincipal struct {
	Principal identity.Principal `json:"principal"`
	Groups    []string           `json:"groups"`
}

func (p *Policy) grantCipher() (cipher.AEAD, error) {
	block, err := aes.NewCipher(p.grantKey)
	if err != nil {
		return nil, ErrForbidden
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrForbidden
	}
	return aead, nil
}
func (p *Policy) SealPrincipal(principal identity.Principal, scope identity.Scope, permission Permission) (string, error) {
	if p.Authorize(principal, scope, permission) != nil {
		return "", ErrForbidden
	}
	aead, err := p.grantCipher()
	if err != nil {
		return "", err
	}
	raw, _ := json.Marshal(queuedPrincipal{principal, principal.Groups})
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", ErrForbidden
	}
	aad := []byte(scope.Key() + "/" + string(permission) + "/" + p.Version())
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, raw, aad)), nil
}
func (p *Policy) OpenPrincipal(token string, scope identity.Scope, permission Permission) (identity.Principal, error) {
	if p == nil || scope.Validate() != nil || len(token) > 65536 {
		return identity.Principal{}, ErrForbidden
	}
	aead, err := p.grantCipher()
	if err != nil {
		return identity.Principal{}, err
	}
	encoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(encoded) < aead.NonceSize()+aead.Overhead() {
		return identity.Principal{}, ErrForbidden
	}
	raw, err := aead.Open(nil, encoded[:aead.NonceSize()], encoded[aead.NonceSize():], []byte(scope.Key()+"/"+string(permission)+"/"+p.Version()))
	if err != nil {
		return identity.Principal{}, ErrForbidden
	}
	var q queuedPrincipal
	if json.Unmarshal(raw, &q) != nil {
		return identity.Principal{}, ErrForbidden
	}
	q.Principal.Groups = q.Groups
	if p.Authorize(q.Principal, scope, permission) != nil {
		return identity.Principal{}, ErrForbidden
	}
	return q.Principal, nil
}
