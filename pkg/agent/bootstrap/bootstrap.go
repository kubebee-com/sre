// sre-agent-init copies Kubernetes-projected bootstrap material into a private
// agent-only volume. It has no network or Kubernetes API capability.
package bootstrap

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
)

func copySecret(source, destination string, limit int64) error {
	f, err := os.Open(source)
	if err != nil {
		return errors.New("bootstrap material unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return errors.New("bootstrap material invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit || (limit == 32 && len(raw) != 32) {
		return errors.New("bootstrap material invalid")
	}
	if destination == "" {
		return errors.New("private destination required")
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".bootstrap-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if err := temp.Chmod(0600); err != nil {
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), destination)
}
func initialize(key, bootstrap, destination string) error {
	if destination == "" {
		return errors.New("private destination required")
	}
	if err := os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.IsDir() {
		return errors.New("private destination invalid")
	}
	if err := os.Chmod(destination, 0700); err != nil {
		return err
	}
	if err := copySecret(key, filepath.Join(destination, "identity.key"), 32); err != nil {
		return err
	}
	if err := copySecret(bootstrap, filepath.Join(destination, "bootstrap"), 128); err != nil {
		return err
	}
	dir, err := os.Open(destination)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Run initializes private enrollment material; it never reads Kubernetes or network state.
func Run(args []string) error {
	f := flag.NewFlagSet("init", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	key := f.String("source-key", "", "projected identity key")
	token := f.String("source-bootstrap", "", "projected bootstrap token")
	dst := f.String("destination", "", "private persistent directory")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("invalid init arguments")
	}
	return initialize(*key, *token, *dst)
}
