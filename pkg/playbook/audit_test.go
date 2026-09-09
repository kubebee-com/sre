package playbook

import (
	"context"
	"github.com/kubebee-com/sre/pkg/remediation"
	"testing"
)

func TestAuditPersistsWithoutLearningOrProvider(t *testing.T) {
	s := serviceResolveFixture(t, nil)
	result, err := s.Resolve(context.Background(), issueFixture(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	settings := s.Settings()
	settings.LearningMode = LearningDisabled
	if err = s.UpdateSettings(settings, "alice"); err != nil {
		t.Fatal(err)
	}
	s.runner = nil
	for _, status := range []remediation.ProposalStatus{remediation.StatusFailed, remediation.StatusCompleted, remediation.StatusRejected, remediation.StatusExpired, remediation.StatusStale} {
		p := *result.Proposal
		p.ID = "audit-" + string(status)
		p.Status = status
		p.VerificationStatus = remediation.VerificationStatusUnverified
		if err = s.RecordOutcome(context.Background(), &p); err != nil {
			t.Fatal(err)
		}
	}
	c := s.catalog.(*MemoryCatalog)
	err = c.backend.read(context.Background(), func(tx catalogTx) error {
		count, err := tx.count(context.Background(), "feedback", "")
		if err != nil {
			return err
		}
		if count != 5 {
			t.Fatalf("audit rows=%d", count)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	stats, _ := s.Status(context.Background())
	if stats.Catalog.LearningCandidates != 0 {
		t.Fatal("audit generated learning")
	}
}
