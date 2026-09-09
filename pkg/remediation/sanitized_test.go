package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
)

func TestProposalJSONSerializationRedactsDiagnosisAndExecutionFields(t *testing.T) {
	proposal := &Proposal{
		ID:     "proposal-1",
		Status: StatusFailed,
		Diagnosis: &triage.Diagnosis{
			Summary:         "password=diagnosis-secret",
			RootCause:       "api_key=diagnosis-key",
			Severity:        scanner.SeverityHigh,
			RemediationPlan: "secret=diagnosis-plan",
			ActionType:      triage.ActionManual,
			ProposedCommand: "kubectl get pods --token=diagnosis-token",
		},
		ExecutionResult: "password=execution-secret",
		ExecutionError:  "api_key=execution-key",
	}

	encoded, err := json.Marshal(proposal)
	if err != nil {
		t.Fatalf("json.Marshal(proposal) error = %v", err)
	}
	serialized := string(encoded)
	for _, raw := range []string{"diagnosis-secret", "diagnosis-key", "diagnosis-plan", "diagnosis-token", "execution-secret", "execution-key"} {
		if strings.Contains(serialized, raw) {
			t.Errorf("proposal JSON leaked %q: %s", raw, serialized)
		}
	}
}
