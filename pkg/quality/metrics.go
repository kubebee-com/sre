package quality

import (
	"github.com/kubebee-com/sre/pkg/incident"
	"math"
)

type Run struct {
	IncidentID     string                  `json:"-"`
	Corroborated   bool                    `json:"corroborated"`
	Invalidated    bool                    `json:"invalidated"`
	Day            string                  `json:"day"`
	ProfileID      string                  `json:"profile_id"`
	ProfileVersion string                  `json:"profile_version"`
	PromptVersion  string                  `json:"prompt_version"`
	RubricVersion  string                  `json:"rubric_version"`
	Status         string                  `json:"status"`
	Reason         string                  `json:"reason"`
	Reviews        []incident.Adjudication `json:"-"`
}
type Interval struct {
	Rate  float64 `json:"rate"`
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}
type Metrics struct {
	EligibleIncidents     int       `json:"eligible_incidents"`
	ReviewedIncidents     int       `json:"reviewed_incidents"`
	CorroboratedIncidents int       `json:"corroborated_incidents"`
	DiagnosticCoverage    float64   `json:"diagnostic_coverage"`
	VerifiedYield         *Interval `json:"verified_yield"`
	Invalidated           int       `json:"invalidated"`
	Attempts              int       `json:"attempts"`
	Reviewed              int       `json:"reviewed"`
	Correct               int       `json:"correct"`
	FactualErrors         int       `json:"factual_errors"`
	Disputed              int       `json:"disputed"`
	Abstentions           int       `json:"abstentions"`
	ProviderFailures      int       `json:"provider_failures"`
	ContextualReviews     int       `json:"contextual_reviews"`
	ReviewedCoverage      float64   `json:"reviewed_coverage"`
	Correctness           *Interval `json:"correctness"`
}

func Aggregate(runs []Run) Metrics {
	m := Metrics{Attempts: len(runs)}
	incidents, reviewed, corroborated := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range runs {
		if r.IncidentID != "" {
			incidents[r.IncidentID] = true
		}
		if r.Status == "INCONCLUSIVE" || r.Status == "NEEDS_EVIDENCE" {
			m.Abstentions++
		}
		if r.Reason == "PROVIDER_UNAVAILABLE" {
			m.ProviderFailures++
		}
		if r.Invalidated {
			m.Invalidated++
			m.Disputed++
			continue
		}
		latest := map[string]string{}
		contextual := false
		for _, review := range r.Reviews {
			switch review.Reason {
			case "CONFIRMED", "FACTUAL_ERROR", "UNRESOLVED":
				if _, ok := latest[review.ActorID]; !ok {
					latest[review.ActorID] = review.Reason
				}
			case "STALE", "NOT_APPLICABLE":
				contextual = true
			}
		}
		if contextual {
			m.ContextualReviews++
		}
		positive, negative := false, false
		for _, reason := range latest {
			positive = positive || reason == "CONFIRMED"
			negative = negative || reason == "FACTUAL_ERROR"
		}
		if positive && negative {
			m.Disputed++
			continue
		}
		if (positive || negative) && r.IncidentID != "" {
			reviewed[r.IncidentID] = true
		}
		if positive && r.Corroborated && r.IncidentID != "" {
			corroborated[r.IncidentID] = true
		}
		if positive {
			m.Reviewed++
			m.Correct++
		}
		if negative {
			m.Reviewed++
			m.FactualErrors++
		}
	}
	if m.Attempts > 0 {
		m.ReviewedCoverage = float64(m.Reviewed) / float64(m.Attempts)
	}
	if m.Reviewed > 0 {
		v := wilson(m.Correct, m.Reviewed)
		m.Correctness = &v
	}
	m.EligibleIncidents = len(incidents)
	m.ReviewedIncidents = len(reviewed)
	m.CorroboratedIncidents = len(corroborated)
	if len(incidents) > 0 {
		m.DiagnosticCoverage = float64(len(reviewed)) / float64(len(incidents))
		v := wilson(len(corroborated), len(incidents))
		m.VerifiedYield = &v
	}
	return m
}

func wilson(successes, total int) Interval {
	n := float64(total)
	p := float64(successes) / n
	z := 1.959963984540054
	den := 1 + z*z/n
	center := (p + z*z/(2*n)) / den
	radius := z * math.Sqrt(p*(1-p)/n+z*z/(4*n*n)) / den
	return Interval{Rate: p, Lower: math.Max(0, center-radius), Upper: math.Min(1, center+radius)}
}
