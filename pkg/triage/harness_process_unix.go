//go:build unix

package triage

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// Isolate the harness so cancellation also stops children holding output pipes.
func configureStructuredCommandCancellation(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
}
