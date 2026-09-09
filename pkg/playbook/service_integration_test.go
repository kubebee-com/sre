package playbook

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/remediation"
	"github.com/kubebee-com/sre/pkg/triage"
	"k8s.io/client-go/kubernetes/fake"
	"testing"
	"time"
)

type executionStub struct{ err error }

func (e executionStub) Execute(context.Context, *remediation.Proposal) (string, error) {
	return "Pod is ready", e.err
}

type verificationStub struct {
	status remediation.VerificationStatus
}

func (v verificationStub) Verify(context.Context, *remediation.Proposal) (remediation.VerificationResult, error) {
	return remediation.VerificationResult{Status: v.status, Message: "Pod readiness observed"}, nil
}
func TestServiceEndToEndVerifiedExecution(t *testing.T) {
	for _, tc := range []struct {
		name     string
		execErr  error
		verified remediation.VerificationStatus
		want     int
	}{{"verified", nil, remediation.VerificationStatusVerified, 1}, {"failed", errors.New("execution failed"), remediation.VerificationStatusVerified, 0}, {"unverified", nil, remediation.VerificationStatusUnavailable, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s := serviceResolveFixture(t, nil)
			baseRunner := s.runner
			s.runner = serviceRunner(func(ctx context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
				if task.Operation == "playbook.learn" {
					return digestRunner(digestFixture())(ctx, task)
				}
				return baseRunner.RunStructured(ctx, task)
			})
			engine := remediation.NewEngineWithVerificationOptions(fake.NewSimpleClientset(), remediation.EngineOptions{Executor: executionStub{tc.execErr}}, remediation.EngineVerificationOptions{Verifier: verificationStub{tc.verified}, OutcomeObserver: s})
			defer engine.Close()
			s.SetProposalCreator(engine)
			r, err := s.Resolve(context.Background(), issueFixture(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			if r.Proposal.Status != remediation.StatusPending {
				t.Fatal(r.Proposal.Status)
			}
			if _, err = engine.Approve(context.Background(), r.Proposal.ID, "alice"); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				p, _ := engine.GetProposal(r.Proposal.ID)
				if p.Status == remediation.StatusCompleted || p.Status == remediation.StatusFailed {
					status, _ := s.Status(context.Background())
					if status.Catalog.LearningCandidates == tc.want {
						if tc.want == 1 {
							if status.Catalog.ReviewPlaybooks != 1 {
								t.Fatal(status)
							}
							if err = s.ObserveOutcome(context.Background(), p); err != nil {
								t.Fatal(err)
							}
							status, _ = s.Status(context.Background())
							if status.Catalog.LearningCandidates != 1 {
								t.Fatal("duplicate candidate")
							}
						}
						return
					}
				}
				time.Sleep(time.Millisecond * 10)
			}
			status, _ := s.Status(context.Background())
			b, _ := json.Marshal(status)
			t.Fatalf("execution did not reach expected learning: %s", b)
		})
	}
}
