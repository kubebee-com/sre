package bootstrap

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInitCreatesPrivateCopiesAndPreservesCredential(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	boot := filepath.Join(dir, "bootstrap")
	os.WriteFile(key, bytes.Repeat([]byte{1}, 32), 0440)
	os.WriteFile(boot, []byte("bootstrap"), 0440)
	dest := filepath.Join(dir, "private")
	if err := initialize(key, boot, dest); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dest, "credential"), []byte("existing"), 0600)
	if err := initialize(key, boot, dest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity.key", "bootstrap", "credential"} {
		st, err := os.Stat(filepath.Join(dest, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("private copy unavailable")
		}
	}
}
