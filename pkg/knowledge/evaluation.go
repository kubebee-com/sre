package knowledge

import (
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"strings"
	"time"
)

const EvaluationVersion = "golden-guidance-eval/v1"

func Suggest(g incident.GoldenCase, observations []privacy.Observation, at time.Time) bool {
	return privacy.SuggestCause(g.CauseCode, observations, at)
}

// Evaluate applies fixed positive/negative and separate held-out perturbations.
// Candidate metadata cannot provide scores or override outcomes.
func Evaluate(g incident.GoldenCase) incident.KnowledgeEvaluation {
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	o := privacy.Observation{Code: privacy.Code(g.CauseCode), ResourceHandle: strings.Repeat("a", 32), ObservedAt: at, ValidUntil: at.Add(time.Minute)}
	healthy := o
	healthy.Code = privacy.Healthy
	stale := o
	stale.ValidUntil = at
	stale.ObservedAt = at.Add(-time.Minute)
	future := o
	future.ObservedAt = at.Add(time.Second)
	future.ValidUntil = at.Add(time.Minute)
	unrelated := o
	unrelated.Code = privacy.DependencyUnavailable
	invalid := o
	invalid.ResourceHandle = "customer-secret"
	cases := []struct {
		observations []privacy.Observation
		want         bool
	}{{[]privacy.Observation{o}, true}, {nil, false}, {[]privacy.Observation{unrelated}, false}, {[]privacy.Observation{o, healthy}, false}, {[]privacy.Observation{stale}, false}, {[]privacy.Observation{future}, false}, {[]privacy.Observation{invalid}, false}, {[]privacy.Observation{unrelated, o}, true}}
	result := incident.KnowledgeEvaluation{Version: EvaluationVersion, BaselineCases: 4, HeldoutCases: 4}
	for _, c := range cases {
		if Suggest(g, c.observations, at) == c.want {
			result.Passed++
		}
	}
	result.Approved = result.Passed == len(cases)
	return result
}
