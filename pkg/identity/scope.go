// Package identity defines the immutable boundaries used by orchestrator services.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var ErrInvalidScope = errors.New("explicit organization, cluster, and application scope required")

type Scope struct {
	OrganizationID string `json:"organization_id"`
	ClusterID      string `json:"cluster_id"`
	ApplicationID  string `json:"application_id"`
}

func ValidID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func (s Scope) Validate() error {
	if !ValidID(s.OrganizationID) || !ValidID(s.ClusterID) || !ValidID(s.ApplicationID) {
		return ErrInvalidScope
	}
	return nil
}

// Key is unambiguous for validated scope IDs. Validate before using it as authority.
func (s Scope) Key() string { return s.OrganizationID + "/" + s.ClusterID + "/" + s.ApplicationID }
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure identity generation unavailable")
	}
	return hex.EncodeToString(b[:])
}
