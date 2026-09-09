package collection

import (
	"bytes"
	"fmt"
	"github.com/kubebee-com/sre/pkg/identity"
	"os"
	"testing"
)

func TestRegistryEncryptsIdentityAndBindsExactTarget(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	dir := t.TempDir()
	r, err := OpenRegistry(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	target := LocalTarget{Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, Kind: "Pod", Namespace: "customer-alice", Name: "alice-private", UID: "uid", ResourceVersion: "7", Epoch: "epoch", Generation: 1}
	handle, commit, err := r.Put(target)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(dir + "/identities.enc")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("alice")) {
		t.Fatal("identity persisted unencrypted")
	}
	reader, err := OpenRegistry(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := reader.Resolve(handle, commit)
	if err != nil || got.Name != target.Name {
		t.Fatal("exact identity lost")
	}
	target.ResourceVersion = "8"
	handle2, commit2, err := r.Put(target)
	if err != nil {
		t.Fatal(err)
	}
	if handle2 != handle || commit2 == commit {
		t.Fatal("target commitment did not bind resource version")
	}
	if _, err := reader.Resolve(handle, commit); err == nil {
		t.Fatal("old target commitment resolved")
	}
	if _, err := OpenRegistry(dir, bytes.Repeat([]byte{8}, 32), true); err == nil {
		t.Fatal("incorrect identity key accepted")
	}
}

func registryTarget() LocalTarget {
	return LocalTarget{Scope: identity.Scope{OrganizationID: "o", ClusterID: "c", ApplicationID: "a"}, Kind: "Pod", Namespace: "ns", Name: "pod", UID: "uid", ResourceVersion: "1", Epoch: "epoch", Generation: 1}
}
func TestRegistryWriterExclusionAndReadOnly(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{1}, 32)
	r, err := OpenRegistry(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OpenRegistry(dir, key, false); err == nil {
		other.Close()
		t.Fatal("second writer accepted")
	}
	h, c, err := r.Put(registryTarget())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenRegistry(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, _, err := reader.Put(registryTarget()); err == nil {
		t.Fatal("read-only mutation accepted")
	}
	if _, err := reader.Resolve(h, c); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, dir + "/identities.enc"} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if p == dir {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("incorrect permissions: %v", info.Mode())
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := OpenRegistry(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Close()
	if _, err := r.Resolve(h, c); err == nil {
		t.Fatal("closed registry resolved")
	}
}
func TestRegistryCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{1}, 32)
	r, err := OpenRegistry(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	h, c, err := r.Put(registryTarget())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenRegistry(dir, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	b, err := os.ReadFile(dir + "/identities.enc")
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 1
	if err := os.WriteFile(dir+"/identities.enc", b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Resolve(h, c); err == nil {
		t.Fatal("corruption used cached authority")
	}
	if _, _, err := r.Put(registryTarget()); err == nil {
		t.Fatal("writer overwrote corruption from cache")
	}
	if other, err := OpenRegistry(dir, key, true); err == nil {
		other.Close()
		t.Fatal("corrupt registry opened")
	}
}
func TestRegistryRejectsInvalidTargetsAndBounds(t *testing.T) {
	r, err := OpenRegistry(t.TempDir(), bytes.Repeat([]byte{1}, 32), false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, change := range []func(*LocalTarget){func(v *LocalTarget) { v.Scope.OrganizationID = "bad/id" }, func(v *LocalTarget) { v.Name = "" }, func(v *LocalTarget) { v.UID = "" }, func(v *LocalTarget) { v.ResourceVersion = "" }, func(v *LocalTarget) { v.Epoch = "" }, func(v *LocalTarget) { v.Generation = -1 }, func(v *LocalTarget) { v.Name = string(bytes.Repeat([]byte{'a'}, 254)) }} {
		v := registryTarget()
		change(&v)
		if _, _, err := r.Put(v); err == nil {
			t.Fatal("invalid target accepted")
		}
	}
	for i := 0; i < maxRegistryEntries; i++ {
		v := registryTarget()
		v.UID = fmt.Sprintf("uid-%d", i)
		h, _ := r.tokens(v)
		r.entries[h] = v
	}
	v := registryTarget()
	if err := r.persist(r.entries); err != nil {
		t.Fatal(err)
	}
	v.UID = "overflow"
	if _, _, err := r.Put(v); err == nil {
		t.Fatal("entry bound exceeded")
	}
}

func TestRegistryFreshNonceAndOversizedSnapshot(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{1}, 32)
	r, err := OpenRegistry(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	h, c, err := r.Put(registryTarget())
	if err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(dir + "/identities.enc")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Put(registryTarget()); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(dir + "/identities.enc")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("encryption nonce reused")
	}
	f, err := os.OpenFile(dir+"/identities.enc", os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxRegistryBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := r.Resolve(h, c); err == nil {
		t.Fatal("oversized snapshot accepted")
	}
}

func TestRegistryRefusesDirectoryReplacementAndModeDrift(t *testing.T) {
	dir := t.TempDir() + "/registry"
	key := bytes.Repeat([]byte{9}, 32)
	r, err := OpenRegistry(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	target := registryTarget()
	_, _, err = r.Put(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Put(target); err == nil {
		t.Fatal("directory mode drift accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+"-old"); err != nil {
		t.Fatal(err)
	}
	replacement, err := OpenRegistry(dir, key, false)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if _, _, err := r.Put(target); err == nil {
		t.Fatal("writer followed replacement directory without its lock")
	}
}
