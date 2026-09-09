package collection

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/kubebee-com/sre/pkg/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	maxRegistryEntries = 10000
	maxRegistryBytes   = 16 << 20
	registrySchema     = "sre-local-targets-v1\n"
)

var errRegistry = errors.New("local target registry unavailable or invalid")

type LocalTarget struct {
	Scope           identity.Scope `json:"scope"`
	Kind            string         `json:"kind"`
	Namespace       string         `json:"namespace"`
	Name            string         `json:"name"`
	UID             string         `json:"uid"`
	ResourceVersion string         `json:"resource_version"`
	Epoch           string         `json:"epoch"`
	Generation      int64          `json:"generation"`
}

type Registry struct {
	mu        sync.Mutex
	dir       string
	directory *os.File
	root      *os.Root
	key       []byte
	aead      cipher.AEAD
	readOnly  bool
	closed    bool
	entries   map[string]LocalTarget
}

// OpenRegistry opens an encrypted, bounded registry. A writer exclusively locks
// the directory for its lifetime; readers observe complete atomic snapshots.
func OpenRegistry(dir string, key []byte, readOnly bool) (*Registry, error) {
	if len(key) != 32 || dir == "" {
		return nil, errRegistry
	}
	if !readOnly {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, errRegistry
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || (readOnly && info.Mode().Perm() != 0700) {
		return nil, errRegistry
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errRegistry
	}
	d, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, errRegistry
	}
	if !readOnly {
		if err := d.Chmod(0700); err != nil {
			d.Close()
			root.Close()
			return nil, errRegistry
		}
		if err := lockRegistry(d); err != nil {
			d.Close()
			root.Close()
			return nil, errRegistry
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		d.Close()
		root.Close()
		return nil, errRegistry
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		d.Close()
		root.Close()
		return nil, errRegistry
	}
	r := &Registry{dir: dir, directory: d, root: root, key: append([]byte(nil), key...), aead: aead, readOnly: readOnly, entries: make(map[string]LocalTarget)}
	if _, err := root.Lstat("identities.enc"); os.IsNotExist(err) && !readOnly {
		err = r.persist(r.entries)
		if err != nil {
			r.Close()
			return nil, errRegistry
		}
	} else if err != nil {
		r.Close()
		return nil, errRegistry
	}
	if err := r.reload(); err != nil {
		r.Close()
		return nil, errRegistry
	}
	return r, nil
}
func validLocalTarget(v LocalTarget) bool {
	if v.Scope.Validate() != nil || !identity.ValidID(v.Kind) || !identity.ValidID(v.Epoch) || v.Generation < 0 {
		return false
	}
	if len(validation.IsDNS1123Subdomain(v.Name)) != 0 || (v.Namespace != "" && len(validation.IsDNS1123Label(v.Namespace)) != 0) {
		return false
	}
	for _, s := range []string{v.UID, v.ResourceVersion} {
		if len(s) == 0 || len(s) > 256 {
			return false
		}
		for _, c := range s {
			if c < 33 || c > 126 {
				return false
			}
		}
	}
	return true
}
func (r *Registry) mac(domain string, v LocalTarget) string {
	b, _ := json.Marshal(v)
	h := hmac.New(sha256.New, r.key)
	h.Write([]byte(domain))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func (r *Registry) tokens(v LocalTarget) (string, string) {
	commitment := r.mac("sre-target-commitment-v1\x00", v)
	v.ResourceVersion = ""
	v.Generation = 0
	return r.mac("sre-target-handle-v1\x00", v)[:32], commitment
}
func (r *Registry) checkDirectory() error {
	named, err := os.Lstat(r.dir)
	if err != nil || !named.IsDir() || named.Mode().Perm() != 0700 {
		return errRegistry
	}
	opened, err := r.directory.Stat()
	if err != nil || !os.SameFile(named, opened) {
		return errRegistry
	}
	return nil
}
func (r *Registry) reload() error {
	if r.checkDirectory() != nil {
		return errRegistry
	}
	info, err := r.root.Lstat("identities.enc")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxRegistryBytes {
		return errRegistry
	}
	f, err := r.root.Open("identities.enc")
	if err != nil {
		return errRegistry
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxRegistryBytes {
		return errRegistry
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRegistryBytes+1))
	if err != nil || len(b) > maxRegistryBytes || len(b) < len(registrySchema)+r.aead.NonceSize()+r.aead.Overhead() {
		return errRegistry
	}
	if !bytes.Equal(b[:len(registrySchema)], []byte(registrySchema)) {
		return errRegistry
	}
	b = b[len(registrySchema):]
	plain, err := r.aead.Open(nil, b[:r.aead.NonceSize()], b[r.aead.NonceSize():], []byte(registrySchema))
	if err != nil {
		return errRegistry
	}
	var values []LocalTarget
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&values); err != nil || values == nil || len(values) > maxRegistryEntries {
		return errRegistry
	}
	if dec.Decode(new(any)) != io.EOF {
		return errRegistry
	}
	entries := make(map[string]LocalTarget, len(values))
	for _, v := range values {
		if !validLocalTarget(v) {
			return errRegistry
		}
		h, _ := r.tokens(v)
		if _, exists := entries[h]; exists {
			return errRegistry
		}
		entries[h] = v
	}
	r.entries = entries
	return nil
}
func (r *Registry) persist(entries map[string]LocalTarget) error {
	if r.checkDirectory() != nil {
		return errRegistry
	}
	if len(entries) > maxRegistryEntries {
		return errRegistry
	}
	values := make([]LocalTarget, 0, len(entries))
	for _, v := range entries {
		values = append(values, v)
	}
	plain, err := json.Marshal(values)
	if err != nil || len(plain)+len(registrySchema)+r.aead.NonceSize()+r.aead.Overhead() > maxRegistryBytes {
		return errRegistry
	}
	nonce := make([]byte, r.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return errRegistry
	}
	data := append([]byte(registrySchema), nonce...)
	data = r.aead.Seal(data, nonce, plain, []byte(registrySchema))
	temporary := ".identities-" + identity.NewID()
	f, err := r.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errRegistry
	}
	defer r.root.Remove(temporary)
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return errRegistry
	}
	if _, err := f.Write(data); err != nil {
		return errRegistry
	}
	if err := f.Sync(); err != nil {
		return errRegistry
	}
	if err := f.Close(); err != nil {
		return errRegistry
	}
	if err := r.root.Rename(temporary, "identities.enc"); err != nil {
		return errRegistry
	}
	if err := r.directory.Sync(); err != nil {
		return errRegistry
	}
	return nil
}
func (r *Registry) Put(v LocalTarget) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.readOnly || !validLocalTarget(v) {
		return "", "", errRegistry
	}
	if err := r.reload(); err != nil {
		return "", "", errRegistry
	}
	h, c := r.tokens(v)
	if _, ok := r.entries[h]; !ok && len(r.entries) >= maxRegistryEntries {
		return "", "", errRegistry
	}
	next := make(map[string]LocalTarget, len(r.entries)+1)
	for k, v := range r.entries {
		next[k] = v
	}
	next[h] = v
	if err := r.persist(next); err != nil {
		return "", "", errRegistry
	}
	r.entries = next
	return h, c, nil
}
func (r *Registry) Resolve(handle, commitment string) (LocalTarget, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || len(handle) != 32 || len(commitment) != 64 {
		return LocalTarget{}, errRegistry
	}
	if err := r.reload(); err != nil {
		return LocalTarget{}, errRegistry
	}
	v, ok := r.entries[handle]
	if !ok {
		return LocalTarget{}, errRegistry
	}
	_, c := r.tokens(v)
	if !hmac.Equal([]byte(c), []byte(commitment)) {
		return LocalTarget{}, errRegistry
	}
	return v, nil
}
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	clear(r.key)
	r.entries = nil
	r.aead = nil
	defer r.root.Close()
	if err := r.directory.Close(); err != nil {
		return errRegistry
	}
	return nil
}

// ReconcileLive removes identities no longer observed by a complete scoped scan.
// A missing mapping denies execution; partial scans must never call this method.
func (r *Registry) ReconcileLive(scope identity.Scope, handles []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.readOnly || scope.Validate() != nil || len(handles) > 10000 {
		return errRegistry
	}
	if r.reload() != nil {
		return errRegistry
	}
	live := map[string]bool{}
	for _, h := range handles {
		if len(h) != 32 {
			return errRegistry
		}
		live[h] = true
	}
	next := map[string]LocalTarget{}
	for h, target := range r.entries {
		if target.Scope != scope || live[h] {
			next[h] = target
		}
	}
	if len(next) == len(r.entries) {
		return nil
	}
	if r.persist(next) != nil {
		return errRegistry
	}
	r.entries = next
	return nil
}
