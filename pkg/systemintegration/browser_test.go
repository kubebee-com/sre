package systemintegration

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func runBrowser(t *testing.T, server string, scope identity.Scope) {
	t.Helper()
	module := os.Getenv("SRE_PLAYWRIGHT_MODULE")
	if module == "" {
		t.Fatal("browser dependency required for Kind acceptance: set SRE_PLAYWRIGHT_MODULE")
	}
	config := map[string]any{"url": server, "scope": scope, "module": module, "chromium": os.Getenv("SRE_CHROMIUM_EXECUTABLE"), "artifacts": os.Getenv("SRE_ENTERPRISE_ARTIFACTS")}
	raw, _ := json.Marshal(config)
	file := filepath.Join(t.TempDir(), "browser.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../scripts/ci/orchestrator-browser.cjs", file)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real browser failed: %v\n%s", err, output)
	}
	t.Log(string(output))
}
