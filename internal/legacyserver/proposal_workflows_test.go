package legacyserver

import (
	"os/exec"
	"testing"
)

func TestProposalBrowserWorkflowContracts(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for frontend workflow tests")
	}
	output, err := exec.Command(node, "static/testdata/proposal-workflows.js").CombinedOutput()
	if err != nil {
		t.Fatalf("frontend workflow: %v\n%s", err, output)
	}
}
