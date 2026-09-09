// Package evaluation runs offline, paired evaluations without granting production authority.
package evaluation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/privacy"
)

const Version = "offline-paired/v1"
const MaxInputBytes = 64 << 10

var ErrInvalid = errors.New("invalid offline evaluation input")

type Dataset struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
	Cases   []Case    `json:"cases"`
	Hash    string    `json:"-"`
}
type Case struct {
	ID       string                           `json:"id"`
	Split    string                           `json:"split"`
	Evidence []investigation.EvidenceSnapshot `json:"evidence"`
	// Empty means the case requires abstention, rather than a cause hypothesis.
	ExpectedCause  privacy.Code `json:"expected_cause"`
	ExpectedHandle string       `json:"expected_handle,omitempty"`
}

func strict(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > MaxInputBytes {
		return ErrInvalid
	}
	canonical, err := incident.CanonicalObject(raw)
	if err != nil {
		return ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	if dec.Decode(dst) != nil {
		return ErrInvalid
	}
	return nil
}
func LoadDataset(raw []byte) (Dataset, error) {
	var d Dataset
	if strict(raw, &d) != nil || !identity.ValidID(d.Version) || d.At.IsZero() || len(d.Cases) < 2 || len(d.Cases) > 256 {
		return Dataset{}, ErrInvalid
	}
	ids := map[string]bool{}
	positive, negative := false, false
	for _, c := range d.Cases {
		if !identity.ValidID(c.ID) || ids[c.ID] || (c.Split != "baseline" && c.Split != "heldout") || len(c.Evidence) > 64 {
			return Dataset{}, ErrInvalid
		}
		ids[c.ID] = true
		refs := map[incident.ItemRef]bool{}
		for _, e := range c.Evidence {
			if !identity.ValidID(e.Ref.ID) || e.Ref.Version < 1 || refs[e.Ref] || e.Observation.Validate() != nil || e.Observation.Source != nil || e.Observation.Target != nil {
				return Dataset{}, ErrInvalid
			}
			refs[e.Ref] = true
		}
		switch c.ExpectedCause {
		case "":
			negative = true
			if c.ExpectedHandle != "" {
				return Dataset{}, ErrInvalid
			}
		case privacy.ResourcePressure, privacy.ConfigurationDrift, privacy.NetworkBlocked:
			positive = true
			if !privacy.ValidHandle(c.ExpectedHandle) {
				return Dataset{}, ErrInvalid
			}
		default:
			return Dataset{}, ErrInvalid
		}
	}
	if !positive || !negative {
		return Dataset{}, ErrInvalid
	}
	canonical, _ := json.Marshal(d)
	sum := sha256.Sum256(canonical)
	d.Hash = hex.EncodeToString(sum[:])
	return d, nil
}

func validVersion(s string) bool {
	if len(s) > 128 {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if !identity.ValidID(part) {
			return false
		}
	}
	return true
}
