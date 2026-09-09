//go:build !unix

package triage

import "os/exec"

// CommandContext kills the direct process; WaitDelay bounds inherited pipes.
func configureStructuredCommandCancellation(cmd *exec.Cmd) {}
