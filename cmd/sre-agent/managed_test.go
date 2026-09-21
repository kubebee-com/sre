package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestManagedMarkerIsOnlyAnEntrypointMarker(t *testing.T) {
	if got := managedArgs([]string{"--managed", "run", "--in-cluster"}); len(got) != 2 || got[0] != "run" || got[1] != "--in-cluster" {
		t.Fatalf("managed arguments = %#v", got)
	}
	if got := managedArgs([]string{"run"}); len(got) != 1 || got[0] != "run" {
		t.Fatalf("ordinary arguments changed: %#v", got)
	}
}

func TestRunWithOrchestratorDoesNotFallBackToLegacyRuntime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", ".", "run", "--orchestrator", "https://127.0.0.1:1")
	cmd.Env = append(os.Environ(), "LLM_PROVIDER=definitely-unsupported")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("managed invocation did not terminate while validating arguments: %v", ctx.Err())
	}
	if err == nil {
		t.Fatal("incomplete managed invocation unexpectedly succeeded")
	}
	text := string(output)
	if strings.Contains(text, "Initializing Kubebee SRE Agent") || strings.Contains(text, "unknown_provider") {
		t.Fatalf("orchestrator invocation fell back to legacy runtime:\n%s", text)
	}
}
