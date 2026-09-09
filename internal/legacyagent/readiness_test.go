package legacyagent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStartupReadinessRequiresSuccessfulScan(t *testing.T) {
	readiness := &startupReadiness{}
	if readiness.Ready() {
		t.Fatal("startup readiness is true before the initial scan")
	}
	readiness.MarkScanResult(errors.New("initial scan failed"))
	if readiness.Ready() {
		t.Fatal("startup readiness is true after an unsuccessful scan")
	}
	readiness.MarkScanResult(nil)
	if !readiness.Ready() {
		t.Fatal("startup readiness is false after a successful scan")
	}
}

func TestServerReadinessIsTiedToInitialScan(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate main.go")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	sourceText := string(source)
	for _, marker := range []string{"initialScanReady", "Readiness:", "runSingleScan", "Store(true)"} {
		if !strings.Contains(sourceText, marker) {
			t.Errorf("main.go missing initial-scan readiness marker %q", marker)
		}
	}
}
