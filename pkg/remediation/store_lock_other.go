//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package remediation

import (
	"errors"
	"os"
)

func lockProposalDirectory(string) (*os.File, error) {
	return nil, errors.New("file-backed proposals require a platform with supported exclusive directory locking")
}
