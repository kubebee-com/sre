package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
	bin := filepath.Join(t.TempDir(), "sre-agent")
	if buildOut, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build sre-agent: %v\n%s", err, buildOut)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--orchestrator", "https://127.0.0.1:1")
	cmd.Env = append(os.Environ(), "OPENAI_PROVIDER=definitely-unsupported")
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
