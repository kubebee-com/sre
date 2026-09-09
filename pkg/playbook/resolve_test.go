package playbook

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	"strings"
	"testing"
)

type proposalFunc func(*scanner.Issue, *triage.Diagnosis, string) (*remediation.Proposal, error)

func (f proposalFunc) CreateProposalForActor(i *scanner.Issue, d *triage.Diagnosis, a string) (*remediation.Proposal, error) {
	return f(i, d, a)
}
func issueFixture() *scanner.Issue {
	return &scanner.Issue{ID: "finding-1", Namespace: "default", Kind: "Pod", Name: "app", TargetUID: "uid-1", TargetResourceVersion: "1", Category: "CrashLoopBackOff", Severity: scanner.SeverityCritical, Summary: "Pod crashing"}
}
func serviceResolveFixture(t *testing.T, change func(*ResolutionPlan)) *Service {
	t.Helper()
	r := serviceRunner(func(ctx context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
		if task.Operation == "playbook.digest" {
			return digestRunner(digestFixture())(ctx, task)
		}
		var input struct {
			Finding  scanner.Issue      `json:"finding"`
			Playbook NormalizedPlaybook `json:"playbook"`
			Evidence []EvidenceRef      `json:"evidence"`
		}
		if err := json.Unmarshal([]byte(task.UserPrompt), &input); err != nil {
			t.Fatal(err)
		}
		p := ResolutionPlan{ID: "model-run", FindingID: input.Finding.ID, PlaybookID: input.Playbook.ID, PlaybookVersion: input.Playbook.Version, Target: ResourceSelector{Namespace: input.Finding.Namespace, Kind: input.Finding.Kind, Name: input.Finding.Name}, TargetUID: input.Finding.TargetUID, ResourceVersion: input.Finding.TargetResourceVersion, Evidence: input.Evidence, Rationale: "Observed pod is crashing", Steps: input.Playbook.Steps, RequiresApproval: true, Confidence: .95, Preconditions: []string{"Pod crashing"}, Postconditions: []string{"Pod ready"}, Verification: []string{"Verify pod ready"}}
		p.Steps[0].EvidenceRefs = []string{input.Evidence[0].ID}
		if change != nil {
			change(&p)
		}
		b, _ := json.Marshal(p)
		return triage.StructuredTaskResult{Text: string(b)}, nil
	})
	s := NewService(NewMemoryCatalog(), r, ServiceOptions{Settings: DefaultServiceSettings(), ProposalCreator: proposalFunc(func(i *scanner.Issue, d *triage.Diagnosis, a string) (*remediation.Proposal, error) {
		return &remediation.Proposal{ID: "proposal-1", IssueID: i.ID, Namespace: i.Namespace, Kind: i.Kind, Name: i.Name, TargetUID: i.TargetUID, TargetResourceVersion: i.TargetResourceVersion, Diagnosis: d, Status: remediation.StatusPending}, nil
	})})
	imp, err := s.Import(context.Background(), ImportRequest{Content: "Restart pod", MediaType: "text/markdown"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Transition(context.Background(), imp.Playbook.ID, 1, LifecycleActive, "alice"); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestResolveGroundedSnapshotAndEvidenceChanges(t *testing.T) {
	s := serviceResolveFixture(t, nil)
	i := issueFixture()
	r, err := s.Resolve(context.Background(), i, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if r.Proposal == nil || r.Proposal.Status != remediation.StatusPending {
		t.Fatal(r)
	}
	i.TargetResourceVersion = "2"
	r2, err := s.Resolve(context.Background(), i, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if r.Plan.Evidence[0].ID == r2.Plan.Evidence[0].ID {
		t.Fatal("reused snapshot id")
	}
}
func TestResolveRejectsUngroundedOrMultipleActions(t *testing.T) {
	cases := map[string]func(*ResolutionPlan){"finding": func(p *ResolutionPlan) { p.FindingID = "other" }, "uid": func(p *ResolutionPlan) { p.TargetUID = "other" }, "rv": func(p *ResolutionPlan) { p.ResourceVersion = "other" }, "action": func(p *ResolutionPlan) { p.Steps[0].Action = "DeleteFailedPod" }, "evidence": func(p *ResolutionPlan) { p.Evidence[0].Summary = "invented" }, "uncertainty": func(p *ResolutionPlan) { p.Uncertainties = []string{"maybe"} }, "multiple": func(p *ResolutionPlan) { x := p.Steps[0]; x.ID = "second"; p.Steps = append(p.Steps, x) }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := serviceResolveFixture(t, change)
			if _, err := s.Resolve(context.Background(), issueFixture(), "alice"); err == nil {
				t.Fatal("unsafe plan accepted")
			}
		})
	}
}

func TestResolveRechecksPolicyAfterProvider(t *testing.T) {
	s := serviceResolveFixture(t, nil)
	base := s.runner
	s.runner = serviceRunner(func(ctx context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
		out, err := base.RunStructured(ctx, task)
		v := s.Settings()
		v.AllowedActions = []string{"DeleteFailedPod"}
		if e := s.UpdateSettings(v, "alice"); e != nil {
			t.Fatal(e)
		}
		return out, err
	})
	if _, err := s.Resolve(context.Background(), issueFixture(), "alice"); err == nil {
		t.Fatal("used stale policy snapshot")
	}
}
func TestResolveRejectsWrongBindingsAndMissingCriteria(t *testing.T) {
	cases := map[string]func(*ResolutionPlan){"playbook": func(p *ResolutionPlan) { p.PlaybookID = "other" }, "version": func(p *ResolutionPlan) { p.PlaybookVersion++ }, "name": func(p *ResolutionPlan) { p.Target.Name = "other" }, "namespace": func(p *ResolutionPlan) { p.Target.Namespace = "other" }, "kind": func(p *ResolutionPlan) { p.Target.Kind = "Deployment" }, "preconditions": func(p *ResolutionPlan) { p.Preconditions = nil }, "verification": func(p *ResolutionPlan) { p.Verification = nil }, "step evidence": func(p *ResolutionPlan) { p.Steps[0].EvidenceRefs = []string{"invented"} }, "command": func(p *ResolutionPlan) { p.Steps[0].Command = "kubectl delete pod app" }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := serviceResolveFixture(t, change)
			if _, err := s.Resolve(context.Background(), issueFixture(), "alice"); err == nil {
				t.Fatal("unsafe plan accepted")
			}
		})
	}
}
func TestResolveMatchesOnlyActiveExactCategoryAndResource(t *testing.T) {
	for _, change := range []func(*scanner.Issue){func(i *scanner.Issue) { i.Category = "other" }, func(i *scanner.Issue) { i.Name = "other" }, func(i *scanner.Issue) { i.Namespace = "other" }, func(i *scanner.Issue) { i.Kind = "Deployment" }} {
		s := serviceResolveFixture(t, nil)
		i := issueFixture()
		change(i)
		out, err := s.Resolve(context.Background(), i, "alice")
		if err != nil || out.Matched || out.Proposal != nil {
			t.Fatalf("%+v %v", out, err)
		}
	}
}

func TestResolutionRetainsDurableFindingContent(t *testing.T) {
	s := serviceResolveFixture(t, nil)
	i := issueFixture()
	i.Details = "container exited with code one"
	i.LogsSnippet = "fatal startup error"
	out, err := s.Resolve(context.Background(), i, "alice")
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.catalog.GetResolution(context.Background(), out.Plan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(run.Evidence[0].Summary, i.Details) || !strings.Contains(run.Evidence[0].Summary, i.LogsSnippet) {
		t.Fatal("durable evidence discarded supplied finding content")
	}
}
