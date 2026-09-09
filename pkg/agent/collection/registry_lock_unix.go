//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package collection

import (
	"golang.org/x/sys/unix"
	"os"
)

func lockRegistry(directory *os.File) error {
	return unix.Flock(int(directory.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
