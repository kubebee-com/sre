//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package collection

import "os"

func lockRegistry(directory *os.File) error { return errRegistry }
