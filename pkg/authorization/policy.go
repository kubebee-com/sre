// Package authorization defines permissions outside prompts and model outputs.
package authorization

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"sort"
	"strings"
	"time"
)

type Role string
type Permission string

const (
	Viewer                Role       = "VIEWER"
	Investigator          Role       = "INVESTIGATOR"
	Owner                 Role       = "OWNER"
	Approver              Role       = "APPROVER"
	Steward               Role       = "STEWARD"
	Administrator         Role       = "ADMINISTRATOR"
	SecurityAdministrator Role       = "SECURITY_ADMINISTRATOR"
	Read                  Permission = "read"
	Investigate           Permission = "investigate"
	Feedback              Permission = "feedback"
	Approve               Permission = "approve"
	Adjudicate            Permission = "adjudicate"
	ReviewKnowledge       Permission = "review_knowledge"
	Setup                 Permission = "setup"
	SecurityPolicy        Permission = "security_policy"
)

var ErrForbidden = errors.New("application permission required")
var permissions = map[Role][]Permission{Viewer: {Read}, Investigator: {Read, Investigate, Feedback}, Owner: {Read, Investigate, Feedback, Approve}, Approver: {Read, Approve}, Steward: {Read, Feedback, Adjudicate, ReviewKnowledge}, Administrator: {Setup}, SecurityAdministrator: {SecurityPolicy}}

type Binding struct {
	Scope identity.Scope `json:"scope"`
	Group string         `json:"group"`
	Role  Role           `json:"role"`
}
type Policy struct {
	grantKey []byte
	bindings []Binding
	version  string
}

func NewPolicy(bindings []Binding) (*Policy, error) {
	if len(bindings) == 0 || len(bindings) > 10000 {
		return nil, ErrForbidden
	}
	copied := append([]Binding(nil), bindings...)
	seen := map[string]bool{}
	for _, b := range copied {
		if b.Scope.Validate() != nil || b.Group == "" || len(b.Group) > 256 || strings.ContainsAny(b.Group, "\r\n\x00") || permissions[b.Role] == nil {
			return nil, ErrForbidden
		}
		key := b.Scope.Key() + "\x00" + b.Group + "\x00" + string(b.Role)
		if seen[key] {
			return nil, ErrForbidden
		}
		seen[key] = true
	}
	sort.Slice(copied, func(i, j int) bool {
		a, _ := json.Marshal(copied[i])
		b, _ := json.Marshal(copied[j])
		return string(a) < string(b)
	})
	encoded, _ := json.Marshal(copied)
	digest := sha256.Sum256(encoded)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, ErrForbidden
	}
	return &Policy{bindings: copied, version: hex.EncodeToString(digest[:]), grantKey: key}, nil
}
func (p *Policy) Version() string {
	if p == nil {
		return ""
	}
	return p.version
}
func (p *Policy) Authorize(principal identity.Principal, scope identity.Scope, permission Permission) error {
	if p == nil || scope.Validate() != nil || !principal.Valid(time.Now()) {
		return ErrForbidden
	}
	for _, b := range p.bindings {
		if b.Scope != scope {
			continue
		}
		for _, group := range principal.Groups {
			if b.Group != group {
				continue
			}
			for _, allowed := range permissions[b.Role] {
				if allowed == permission {
					return nil
				}
			}
		}
	}
	return ErrForbidden
}
func (p *Policy) Scopes(principal identity.Principal) []identity.Scope {
	scopes := []identity.Scope{}
	if p == nil {
		return scopes
	}
	seen := map[string]bool{}
	for _, b := range p.bindings {
		if !seen[b.Scope.Key()] && p.Authorize(principal, b.Scope, Read) == nil {
			scopes = append(scopes, b.Scope)
			seen[b.Scope.Key()] = true
		}
	}
	return scopes
}

// ScopesFor returns only scopes where the caller has the requested permission.
func (p *Policy) ScopesFor(principal identity.Principal, permission Permission) []identity.Scope {
	result := []identity.Scope{}
	seen := map[string]bool{}
	for _, b := range p.bindings {
		if !seen[b.Scope.Key()] && p.Authorize(principal, b.Scope, permission) == nil {
			seen[b.Scope.Key()] = true
			result = append(result, b.Scope)
		}
	}
	return result
}
