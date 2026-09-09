package investigation

import (
	"errors"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"time"
)

var ErrInvalidConclusion = errors.New("conclusion lacks valid scoped evidence")

// AssessCandidate evaluates citation/relevance sufficiency. It never grants
// CORROBORATED: that requires an independent authorized rubric assessment.
func AssessCandidate(candidate Conclusion, evidence []EvidenceSnapshot, at time.Time) (Assessment, error) {
	result := Assessment{Status: NeedsEvidence, ReasonCode: "MISSING_DIRECT_EVIDENCE", Conclusion: candidate}
	probe := privacy.Observation{Code: candidate.CauseCode, ResourceHandle: candidate.ResourceHandle, ObservedAt: at, ValidUntil: at.Add(time.Minute)}
	if probe.Validate() != nil {
		return result, ErrInvalidConclusion
	}
	if !privacy.ValidHandle(candidate.ResourceHandle) || len(candidate.SupportingEvidence) > 32 || len(candidate.ContradictingEvidence) > 32 || len(candidate.Alternatives) > 8 {
		return result, ErrInvalidConclusion
	}
	if len(candidate.RequestedChecks) > 2 {
		return result, ErrInvalidConclusion
	}
	for _, check := range candidate.RequestedChecks {
		if !privacy.ValidHandle(check.ResourceHandle) || (check.Kind != "REFRESH_RESOURCE_STATE" && check.Kind != "REFRESH_DEPENDENCIES") {
			return result, ErrInvalidConclusion
		}
		found := false
		for _, e := range evidence {
			if e.Observation.ResourceHandle == check.ResourceHandle {
				found = true
			}
		}
		if !found {
			return result, ErrInvalidConclusion
		}
	}
	byRef := map[incident.ItemRef]privacy.Observation{}
	for _, item := range evidence {
		if item.Observation.Validate() != nil || item.Observation.ObservedAt.After(at) || !item.Observation.ValidUntil.After(at) {
			continue
		}
		byRef[item.Ref] = item.Observation
	}
	direct := false
	for _, ref := range candidate.SupportingEvidence {
		observation, ok := byRef[ref]
		if !ok {
			return result, ErrInvalidConclusion
		}
		if observation.Code == candidate.CauseCode && observation.ResourceHandle == candidate.ResourceHandle {
			direct = true
		}
	}
	for _, ref := range candidate.ContradictingEvidence {
		if _, ok := byRef[ref]; !ok {
			return result, ErrInvalidConclusion
		}
	}
	for _, alternative := range candidate.Alternatives {
		probe := privacy.Observation{Code: alternative.CauseCode, ResourceHandle: candidate.ResourceHandle, ObservedAt: at, ValidUntil: at.Add(time.Minute)}
		if probe.Validate() != nil || len(alternative.DiscriminatingEvidence) > 32 {
			return result, ErrInvalidConclusion
		}
		for _, ref := range alternative.DiscriminatingEvidence {
			if _, ok := byRef[ref]; !ok {
				return result, ErrInvalidConclusion
			}
		}
	}
	// Deterministic contradiction checks do not depend on model disclosure.
	for _, observation := range byRef {
		if observation.ResourceHandle == candidate.ResourceHandle && observation.Code == privacy.Healthy && candidate.CauseCode != privacy.Healthy {
			result.Status = Inconclusive
			result.ReasonCode = "OBSERVED_HEALTH_CONTRADICTION"
			return result, nil
		}
	}
	if len(candidate.ContradictingEvidence) > 0 {
		result.Status = Inconclusive
		result.ReasonCode = "MATERIAL_CONTRADICTION"
		return result, nil
	}
	if !direct {
		return result, nil
	}
	switch candidate.CauseCode {
	case privacy.CrashLoop, privacy.PodFailed, privacy.DependencyUnavailable:
		result.ReasonCode = "SYMPTOM_REQUIRES_UPSTREAM_EVIDENCE"
		return result, nil
	case privacy.ReadUnavailable, privacy.Healthy, privacy.Unclassified:
		return result, nil
	}
	result.Status = Hypothesis
	result.ReasonCode = "INDEPENDENT_CAUSAL_REVIEW_REQUIRED"
	return result, nil
}
