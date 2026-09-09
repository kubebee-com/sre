package playbook

import (
	"context"
	"github.com/kubebee-com/sre/pkg/remediation"
	"sync"
	"testing"
)

func TestLearnOnlyVerifiedMutationAndIdempotent(t *testing.T) {
	s := serviceResolveFixture(t, nil)
	r, err := s.Resolve(context.Background(), issueFixture(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	s.runner = digestRunner(digestFixture())
	p := r.Proposal
	for _, status := range []remediation.ProposalStatus{remediation.StatusFailed, remediation.StatusPending, remediation.StatusCompleted} {
		p.ID = "proposal-" + string(status)
		p.Status = status
		p.VerificationStatus = remediation.VerificationStatusUnverified
		if err = s.ObserveOutcome(context.Background(), p); err != nil {
			t.Fatal(err)
		}
	}
	stat, _ := s.Status(context.Background())
	if stat.Catalog.LearningCandidates != 0 {
		t.Fatal("unverified learning")
	}
	p.ID = "proposal-verified"
	p.Status = remediation.StatusCompleted
	p.VerificationStatus = remediation.VerificationStatusVerified
	p.ExecutionResult = "Pod ready"
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.ObserveOutcome(context.Background(), p) }()
	}
	wg.Wait()
	close(errs)
	for err = range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	stat, _ = s.Status(context.Background())
	if stat.Catalog.LearningCandidates != 1 || stat.Catalog.ReviewPlaybooks != 1 {
		t.Fatalf("%+v", stat)
	}
}
func TestLearningModesAndForgedLineage(t *testing.T) {
	for _, mode := range []LearningMode{LearningDisabled, LearningObserveOnly, LearningAutoDraft} {
		t.Run(string(mode), func(t *testing.T) {
			s := serviceResolveFixture(t, nil)
			r, err := s.Resolve(context.Background(), issueFixture(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			s.runner = digestRunner(digestFixture())
			v := s.Settings()
			v.LearningMode = mode
			if err = s.UpdateSettings(v, "alice"); err != nil {
				t.Fatal(err)
			}
			p := r.Proposal
			p.Status = remediation.StatusCompleted
			p.VerificationStatus = remediation.VerificationStatusVerified
			p.ExecutionResult = "Pod ready"
			if mode == LearningAutoDraft {
				p.TargetUID = "forged"
			}
			err = s.ObserveOutcome(context.Background(), p)
			if mode == LearningAutoDraft && err == nil {
				t.Fatal("forged lineage accepted")
			}
			stat, _ := s.Status(context.Background())
			if stat.Catalog.LearningCandidates != 0 {
				t.Fatal("unexpected draft")
			}
		})
	}
}
