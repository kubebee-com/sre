package authorization

import (
	"crypto/hmac"
	"crypto/sha256"
	"github.com/kubebee-com/sre/pkg/identity"
)

// SetGrantKey configures shared queued authority before the policy is served.
// Generation rotation invalidates existing grants even if the master key remains.
// Callers must provide the same secret and generation to every replica.
func (p *Policy) SetGrantKey(master []byte, generation string) error {
	if p == nil || len(master) != 32 || !identity.ValidID(generation) {
		return ErrForbidden
	}
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte("sre-queued-authority/v1/" + generation))
	p.grantKey = mac.Sum(nil)
	return nil
}
