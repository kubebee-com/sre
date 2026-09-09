package quality

import (
	"github.com/kubebee-com/sre/pkg/incident"
	"testing"
)

func TestQualityUsesReviewedDenominatorAndUnknownIsNotSuccess(t *testing.T) {
	r := Aggregate([]Run{{Status: "HYPOTHESIS"}, {Status: "INCONCLUSIVE", Reason: "PROVIDER_UNAVAILABLE"}, {Status: "NEEDS_EVIDENCE"}})
	if r.Attempts != 3 || r.Correctness != nil || r.Reviewed != 0 || r.ProviderFailures != 1 || r.Abstentions != 2 {
		t.Fatalf("fabricated success %+v", r)
	}
	r = Aggregate([]Run{{Reviews: []incident.Adjudication{{ActorID: "a", Reason: "CONFIRMED"}}}, {Reviews: []incident.Adjudication{{ActorID: "a", Reason: "FACTUAL_ERROR"}}}, {}})
	if r.Reviewed != 2 || r.Correctness == nil || r.Correctness.Rate != 0.5 || r.Correctness.Lower >= 0.5 || r.Correctness.Upper <= 0.5 {
		t.Fatal("incorrect denominator or interval", r)
	}
	r = Aggregate([]Run{{Reviews: []incident.Adjudication{{ActorID: "b", Reason: "STALE"}, {ActorID: "a", Reason: "CONFIRMED"}}}})
	if r.Correct != 1 {
		t.Fatal("context rewrote historical truth")
	}
	r = Aggregate([]Run{{Reviews: []incident.Adjudication{{ActorID: "a", Reason: "CONFIRMED"}, {ActorID: "b", Reason: "FACTUAL_ERROR"}}}})
	if r.Reviewed != 0 || r.Disputed != 1 {
		t.Fatal("conflicting reviews became success")
	}
}

func TestUnresolvedAdjudicationWithdrawsEarlierFactualCertainty(t *testing.T) {
	r := Aggregate([]Run{{Reviews: []incident.Adjudication{{ActorID: "a", Reason: "UNRESOLVED"}, {ActorID: "a", Reason: "CONFIRMED"}}}})
	if r.Correctness != nil || r.Correct != 0 {
		t.Fatal("withdrawn review still counted as success", r)
	}
}

func TestInvalidatedLineageCannotInflateReviewedSuccess(t *testing.T) {
	r := Aggregate([]Run{{Invalidated: true, Reviews: []incident.Adjudication{{ActorID: "a", Reason: "CONFIRMED"}}}})
	if r.Attempts != 1 || r.Correctness != nil || r.Invalidated != 1 || r.Disputed != 1 {
		t.Fatal("invalidated diagnosis counted as success", r)
	}
}

func TestIncidentYieldDoesNotCountRetriesAsNewSuccessfulIncidents(t *testing.T) {
	review := []incident.Adjudication{{ActorID: "reviewer", Reason: "CONFIRMED"}}
	r := Aggregate([]Run{{IncidentID: "same", Corroborated: true, Reviews: review}, {IncidentID: "same", Corroborated: true, Reviews: review}, {IncidentID: "pending", Status: "QUEUED"}})
	if r.Attempts != 3 || r.EligibleIncidents != 2 || r.CorroboratedIncidents != 1 || r.ReviewedIncidents != 1 || r.VerifiedYield == nil || r.VerifiedYield.Rate != 0.5 {
		t.Fatal("retry inflated verified yield", r)
	}
}
