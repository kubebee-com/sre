package triage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestHarnessStructuredCancellationAfterStart(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	descendantMarker := marker + "-descendant"
	provider := NewHarnessProvider("/bin/sh", []string{"-c", `echo started > "$1"; (sleep 0.2; echo survived > "$2") & sleep 2; echo '{}'`, "harness", marker, descendantMarker})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := provider.RunStructured(ctx, StructuredTask{Operation: "playbook.digest", SystemPrompt: "system", UserPrompt: "user"})
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("harness did not start")
		}
		time.Sleep(time.Millisecond)
	}
	// Let the shell launch the descendant that inherits its output pipes.
	time.Sleep(25 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancellation waited for descendant output pipes")
	}
	if runtime.GOOS == "linux" {
		time.Sleep(300 * time.Millisecond)
		if _, err := os.Stat(descendantMarker); !os.IsNotExist(err) {
			t.Fatalf("descendant survived cancellation: %v", err)
		}
	}

}
