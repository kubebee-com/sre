package orchestrator

import (
	"os/exec"
	"testing"
)

func TestFeedbackUIContracts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node required for executable UI contract")
	}
	output, err := exec.Command(node, "static/testdata/feedback.js").CombinedOutput()
	if err != nil {
		t.Fatalf("UI contract: %v\n%s", err, output)
	}
}

func TestReconciliationUIContracts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node required for executable UI contract")
	}
	output, err := exec.Command(node, "static/testdata/reconcile.js").CombinedOutput()
	if err != nil {
		t.Fatalf("UI contract: %v\n%s", err, output)
	}
}
