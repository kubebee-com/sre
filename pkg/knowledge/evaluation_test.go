package knowledge

import (
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"testing"
	"time"
)

func TestGoldenGuidanceRequiresFreshMatchingEvidence(t *testing.T) {
	g := incident.GoldenCase{CauseCode: "NETWORK_BLOCKED"}
	at := time.Now()
	if Suggest(g, nil, at) {
		t.Fatal("golden case supplied facts")
	}
	if !Evaluate(g).Approved {
		t.Fatal("safe guidance failed frozen evaluation")
	}
	g.CauseCode = "CRASH_LOOP"
	if Evaluate(g).Approved {
		t.Fatal("symptom promoted to golden root cause")
	}
	if Suggest(g, []privacy.Observation{{Code: privacy.Healthy}}, at) {
		t.Fatal("healthy observation used as cause")
	}
}
