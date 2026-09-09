package legacyagent

import (
	"context"
	"github.com/kubebee-com/sre/pkg/remediation"
	"testing"
)

type countingProposalNotifier struct{ calls int }

func (n *countingProposalNotifier) NotifyProposalCreated(context.Context, *remediation.Proposal) error {
	n.calls++
	return nil
}
func TestNotifyNewProposalSuppressesReusedProposals(t *testing.T) {
	n := &countingProposalNotifier{}
	known := map[string]bool{"existing": true}
	for _, id := range []string{"existing", "new", "new"} {
		if err := notifyNewProposal(context.Background(), n, &remediation.Proposal{ID: id}, known); err != nil {
			t.Fatal(err)
		}
	}
	if n.calls != 1 {
		t.Fatalf("notifications = %d, want 1", n.calls)
	}
}
