package investigation

import (
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"strings"
	"testing"
	"time"
)

func TestFrozenDiagnosticBaseline(t *testing.T) {
	at := time.Now()
	upstream := strings.Repeat("a", 32)
	downstream := strings.Repeat("b", 32)
	evidence := []EvidenceSnapshot{{Ref: incident.ItemRef{ID: "network", Version: 1}, Observation: privacy.Observation{Code: privacy.NetworkBlocked, ResourceHandle: upstream, ObservedAt: at, ValidUntil: at.Add(time.Minute)}}, {Ref: incident.ItemRef{ID: "symptom", Version: 1}, Observation: privacy.Observation{Code: privacy.DependencyUnavailable, ResourceHandle: downstream, DependencyHandles: []string{upstream}, ObservedAt: at, ValidUntil: at.Add(time.Minute)}}}
	good := Conclusion{CauseCode: privacy.NetworkBlocked, ResourceHandle: upstream, SupportingEvidence: []incident.ItemRef{evidence[0].Ref, evidence[1].Ref}}
	result, err := AssessCandidate(good, evidence, at)
	if err != nil || result.Status != Hypothesis {
		t.Fatalf("plausible cause: %#v %v", result, err)
	}
	cases := map[string]Conclusion{"downstream-only": {CauseCode: privacy.NetworkBlocked, ResourceHandle: upstream, SupportingEvidence: []incident.ItemRef{evidence[1].Ref}}, "invented-citation": {CauseCode: privacy.NetworkBlocked, ResourceHandle: upstream, SupportingEvidence: []incident.ItemRef{{ID: "invented", Version: 1}}}, "contradicted": {CauseCode: privacy.NetworkBlocked, ResourceHandle: upstream, SupportingEvidence: []incident.ItemRef{evidence[0].Ref}, ContradictingEvidence: []incident.ItemRef{evidence[1].Ref}}, "unrelated-target": {CauseCode: privacy.NetworkBlocked, ResourceHandle: downstream, SupportingEvidence: []incident.ItemRef{evidence[0].Ref}}}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := AssessCandidate(candidate, evidence, at)
			if err == nil && result.Status == Hypothesis {
				t.Fatal("unsupported cause accepted")
			}
		})
	}
	result, err = AssessCandidate(good, evidence, at.Add(time.Hour))
	if err == nil && result.Status == Hypothesis {
		t.Fatal("stale evidence accepted")
	}
	if result.Status == Corroborated {
		t.Fatal("model confidence cannot corroborate")
	}
}

func TestProviderCannotOmitObservedContradiction(t *testing.T) {
	at := time.Now()
	handle := strings.Repeat("c", 32)
	evidence := []EvidenceSnapshot{{Ref: incident.ItemRef{ID: "bad", Version: 1}, Observation: privacy.Observation{Code: privacy.NetworkBlocked, ResourceHandle: handle, ObservedAt: at.Add(-time.Second), ValidUntil: at.Add(time.Minute)}}, {Ref: incident.ItemRef{ID: "good", Version: 1}, Observation: privacy.Observation{Code: privacy.Healthy, ResourceHandle: handle, ObservedAt: at, ValidUntil: at.Add(time.Minute)}}}
	result, err := AssessCandidate(Conclusion{CauseCode: privacy.NetworkBlocked, ResourceHandle: handle, SupportingEvidence: []incident.ItemRef{{ID: "bad", Version: 1}}}, evidence, at)
	if err != nil || result.Status != Inconclusive {
		t.Fatalf("omitted contradiction accepted: %+v %v", result, err)
	}
}

func TestSymptomAloneCannotBecomeRootCauseHypothesis(t *testing.T) {
	at := time.Now()
	o := privacy.Observation{Code: privacy.CrashLoop, ResourceHandle: strings.Repeat("a", 32), ObservedAt: at, ValidUntil: at.Add(time.Minute)}
	ref := incident.ItemRef{ID: "symptom", Version: 1}
	result, err := AssessCandidate(Conclusion{CauseCode: privacy.CrashLoop, ResourceHandle: o.ResourceHandle, SupportingEvidence: []incident.ItemRef{ref}}, []EvidenceSnapshot{{Ref: ref, Observation: o}}, at)
	if err != nil || result.Status != NeedsEvidence {
		t.Fatalf("shallow cause %+v %v", result, err)
	}
}
