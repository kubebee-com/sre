//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package remediation

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Lock the directory inode so atomically replacing proposals.json cannot
// replace the lock. The descriptor stays open for the store's lifetime.
func lockProposalDirectory(dir string) (*os.File, error) {
	file, err := os.Open(dir)
	if err != nil {
		return nil, errors.New("proposal directory is unavailable")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("proposal directory is already in use or does not support exclusive locking")
	}
	return file, nil
}
