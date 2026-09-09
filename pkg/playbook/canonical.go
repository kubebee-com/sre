package playbook

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

func CanonicalHash(value any) (string, error) {
	encoded, err := json.Marshal(canonicalValue(value))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return strings.ToLower(hex.EncodeToString(sum[:])), nil
}

func canonicalValue(value any) any {
	switch typed := value.(type) {
	case NormalizedPlaybook:
		return canonicalNormalizedPlaybook(typed)
	case *NormalizedPlaybook:
		if typed == nil {
			return typed
		}
		return canonicalNormalizedPlaybook(*typed)
	case ResolutionPlan:
		return canonicalResolutionPlan(typed)
	case *ResolutionPlan:
		if typed == nil {
			return typed
		}
		return canonicalResolutionPlan(*typed)
	case EvidenceRef:
		return canonicalEvidenceRef(typed)
	case *EvidenceRef:
		if typed == nil {
			return typed
		}
		return canonicalEvidenceRef(*typed)
	default:
		return value
	}
}

func canonicalNormalizedPlaybook(input NormalizedPlaybook) NormalizedPlaybook {
	out := input
	out.Version = 0
	out.Lifecycle = ""
	out.CreatedAt = time.Time{}
	out.CanonicalHash = ""
	out.SourceIDs = sortedStrings(input.SourceIDs)
	out.Lineage = sortedStrings(input.Lineage)
	out.FailureCategories = sortedStrings(input.FailureCategories)
	out.TriggerConditions = sortedStrings(input.TriggerConditions)
	out.Applicability = sortedSelectors(input.Applicability)
	out.Evidence = canonicalEvidence(input.Evidence)
	out.Preconditions = sortedStrings(input.Preconditions)
	out.Postconditions = sortedStrings(input.Postconditions)
	out.Unknowns = sortedStrings(input.Unknowns)

	out.Steps = canonicalSteps(input.Steps)
	return out
}

func canonicalResolutionPlan(input ResolutionPlan) ResolutionPlan {
	out := input
	out.CreatedAt = time.Time{}
	out.TargetUID = ""
	out.ResourceVersion = ""
	out.Evidence = canonicalEvidence(input.Evidence)
	out.Uncertainties = sortedStrings(input.Uncertainties)
	out.Preconditions = sortedStrings(input.Preconditions)
	out.Postconditions = sortedStrings(input.Postconditions)
	out.Verification = sortedStrings(input.Verification)
	out.Steps = canonicalSteps(input.Steps)
	return out
}

func canonicalSteps(input []NormalizedStep) []NormalizedStep {
	out := append([]NormalizedStep(nil), input...)
	for index := range out {
		out[index].TargetReplicas = cloneTargetReplicas(out[index].TargetReplicas)
		out[index].Targets = sortedSelectors(out[index].Targets)
		out[index].EvidenceRefs = sortedStrings(out[index].EvidenceRefs)
		out[index].Preconditions = sortedStrings(out[index].Preconditions)
		out[index].Postconditions = sortedStrings(out[index].Postconditions)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return stepSortKey(out[i]) < stepSortKey(out[j])
	})
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func canonicalEvidence(values []EvidenceRef) []EvidenceRef {
	out := make([]EvidenceRef, len(values))
	for index, value := range values {
		out[index] = canonicalEvidenceRef(value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return evidenceSortKey(out[i]) < evidenceSortKey(out[j])
	})
	return out
}

func canonicalEvidenceRef(value EvidenceRef) EvidenceRef {
	value.UID = ""
	value.ResourceVersion = ""
	return value
}

func sortedSelectors(values []ResourceSelector) []ResourceSelector {
	out := append([]ResourceSelector(nil), values...)
	sort.SliceStable(out, func(i, j int) bool {
		return selectorSortKey(out[i]) < selectorSortKey(out[j])
	})
	return out
}

func evidenceSortKey(e EvidenceRef) string {
	return strings.Join([]string{e.ID, e.SourceID, e.Kind, e.Namespace, e.Name, e.UID, e.ResourceVersion, e.FieldPath, e.Summary, e.Hash}, "\x00")
}

func selectorSortKey(s ResourceSelector) string {
	return strings.Join([]string{s.Namespace, s.Kind, s.Name, s.LabelSelector}, "\x00")
}

func stepSortKey(s NormalizedStep) string {
	return strings.Join([]string{s.ID, s.Action, s.Title, s.Description}, "\x00")
}

func cloneTargetReplicas(value *int32) *int32 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
