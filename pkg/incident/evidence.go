package incident

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/identity"
	"io"
	"sort"
)

var ErrInvalidItem = errors.New("invalid immutable diagnostic item")

// Seal validates and hashes the complete immutable envelope. The repository
// repeats this operation and never accepts a caller's hash as authoritative.
func (i *Item) Seal() error {
	if i == nil || i.Scope.Validate() != nil || !identity.ValidID(i.IncidentID) || !identity.ValidID(i.ID) || i.Version < 1 || (i.Kind != Evidence && i.Kind != Claim) || i.ObservedAt.IsZero() || !i.ValidUntil.After(i.ObservedAt) || len(i.Parents) > 64 {
		return ErrInvalidItem
	}
	body, err := CanonicalObject(i.Body)
	if err != nil {
		return ErrInvalidItem
	}
	parents := append([]ItemRef{}, i.Parents...)
	sort.Slice(parents, func(a, b int) bool {
		if parents[a].ID == parents[b].ID {
			return parents[a].Version < parents[b].Version
		}
		return parents[a].ID < parents[b].ID
	})
	for n, p := range parents {
		if !identity.ValidID(p.ID) || p.Version < 1 || (p.ID == i.ID && p.Version == i.Version) || (n > 0 && p == parents[n-1]) {
			return ErrInvalidItem
		}
	}
	sealed := *i
	sealed.Body = body
	sealed.Parents = parents
	sealed.ObservedAt = sealed.ObservedAt.UTC()
	sealed.ValidUntil = sealed.ValidUntil.UTC()
	sealed.Hash = ""
	encoded, err := json.Marshal(sealed)
	if err != nil {
		return ErrInvalidItem
	}
	digest := sha256.Sum256(encoded)
	sealed.Hash = hex.EncodeToString(digest[:])
	*i = sealed
	return nil
}

// CanonicalObject rejects duplicate keys at every depth and retains exact JSON
// numbers. A float64 decode would silently change large observation counters.
func CanonicalObject(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrInvalidItem
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := readValue(d, 0)
	if err != nil {
		return nil, ErrInvalidItem
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, ErrInvalidItem
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalidItem
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > 65536 {
		return nil, ErrInvalidItem
	}
	return data, nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrInvalidItem
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, ErrInvalidItem
			}
			if _, exists := object[name]; exists {
				return nil, ErrInvalidItem
			}
			v, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[name] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInvalidItem
		}
		return object, nil
	case '[':
		values := []any{}
		for d.More() {
			v, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInvalidItem
		}
		return values, nil
	default:
		return nil, ErrInvalidItem
	}
}
