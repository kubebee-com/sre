package remediation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestCreateProposalRejectsUncheckedUnsafeDiagnosis(t *testing.T) {
	engine := NewEngine(k8sfake.NewSimpleClientset())
	issue := &scanner.Issue{ID: "issue-engine", Namespace: "default", Kind: "Pod", Name: "payments"}
	unsafe := &triage.Diagnosis{
		IssueID:         issue.ID,
		Summary:         "summary",
		RootCause:       "root",
		Severity:        scanner.SeverityHigh,
		RemediationPlan: "plan",
		ActionType:      triage.ActionManual,
		ProposedCommand: "kubectl delete namespace production",
		ConfidenceScore: 0.5,
	}
	if proposal := engine.CreateProposal(issue, unsafe); proposal != nil {
		t.Fatalf("CreateProposal() accepted unsafe diagnosis: %#v", proposal)
	}
}

func TestDirectProposalAndSanitizedProposalSerializationUsesConfiguredDefaultRedactor(t *testing.T) {
	secret := "proposal-process-default-secret"
	sanitizer.ConfigureDefaultRedactor(secret)
	t.Cleanup(func() { sanitizer.ConfigureDefaultRedactor() })
	proposal := Proposal{
		ID:     "proposal-direct",
		Status: StatusPending,
		Diagnosis: &triage.Diagnosis{
			Summary:         "summary " + secret,
			RootCause:       "root",
			Severity:        scanner.SeverityHigh,
			RemediationPlan: "plan",
			ActionType:      triage.ActionManual,
			ProposedCommand: "kubectl get pods -n default",
			ConfidenceScore: 0.5,
		},
	}
	projection := &SanitizedProposal{ID: "projection-direct", ExecutionResult: "result " + secret}
	for name, value := range map[string]interface{}{"proposal": proposal, "projection": projection} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error = %v", name, err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Errorf("json.Marshal(%s) leaked configured literal: %s", name, encoded)
		}
	}
}
