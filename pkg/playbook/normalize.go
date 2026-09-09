package playbook

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var slugSeparatorRegex = regexp.MustCompile(`[^a-z0-9]+`)

func NormalizeDigest(digest PlaybookDigest) (NormalizedPlaybook, error) {
	if err := digest.Validate(); err != nil {
		return NormalizedPlaybook{}, err
	}

	steps := append([]DigestStep(nil), digest.Steps...)
	sort.SliceStable(steps, func(i, j int) bool {
		left := digestStepSortKey(steps[i])
		right := digestStepSortKey(steps[j])
		return left < right
	})

	normalizedSteps := make([]NormalizedStep, 0, len(steps))
	for index, step := range steps {
		id := slug(step.ID)
		if id == "" {
			id = fmt.Sprintf("step-%03d", index+1)
		}
		action := strings.TrimSpace(step.Action)
		if action == "" {
			action = "Manual"
		}
		normalizedSteps = append(normalizedSteps, NormalizedStep{
			ID:             id,
			Order:          index + 1,
			Title:          strings.TrimSpace(step.Title),
			Description:    strings.TrimSpace(step.Description),
			Action:         action,
			Command:        strings.TrimSpace(step.Command),
			TargetReplicas: cloneTargetReplicas(step.TargetReplicas),
			Targets:        normalizeSelectors(step.Targets),
			EvidenceRefs:   normalizeList(step.EvidenceRefs),
			Preconditions:  normalizeList(step.Preconditions),
			Postconditions: normalizeList(step.Postconditions),
			ObserveOnly:    step.ObserveOnly,
			Confidence:     step.Confidence,
		})
	}

	playbook := NormalizedPlaybook{
		ID:                slug(digest.ID),
		Version:           1,
		Lifecycle:         LifecycleNormalized,
		Title:             strings.TrimSpace(digest.Title),
		Summary:           strings.TrimSpace(digest.Summary),
		SourceIDs:         normalizeList([]string{digest.SourceID}),
		Lineage:           normalizeList(digest.Lineage),
		FailureCategories: normalizeList(digest.FailureCategories),
		TriggerConditions: normalizeList(digest.TriggerConditions),
		Evidence:          normalizeEvidence(digest.Evidence),
		Preconditions:     normalizeList(digest.Preconditions),
		Steps:             normalizedSteps,
		Postconditions:    normalizeList(digest.Postconditions),
		Rollback:          strings.TrimSpace(digest.Rollback),
		ApprovalPolicy:    strings.TrimSpace(digest.ApprovalIntent),
		Unknowns:          normalizeList(digest.Unknowns),
		Confidence:        digest.Confidence,
	}
	if playbook.ID == "" {
		playbook.ID = "playbook"
	}
	if err := playbook.Validate(); err != nil {
		return NormalizedPlaybook{}, err
	}
	hash, err := CanonicalHash(playbook)
	if err != nil {
		return NormalizedPlaybook{}, err
	}
	playbook.CanonicalHash = hash
	return playbook, nil
}

func digestStepSortKey(step DigestStep) string {
	order := ""
	if step.Order > 0 {
		order = fmt.Sprintf("%010d", step.Order)
	}
	return strings.Join([]string{
		order,
		strings.TrimSpace(step.ID),
		strings.TrimSpace(step.Action),
		strings.TrimSpace(step.Title),
		strings.TrimSpace(step.Description),
	}, "\x00")
}

func normalizeEvidence(values []EvidenceRef) []EvidenceRef {
	out := make([]EvidenceRef, 0, len(values))
	for _, evidence := range values {
		evidence.ID = strings.TrimSpace(evidence.ID)
		evidence.SourceID = strings.TrimSpace(evidence.SourceID)
		evidence.Kind = canonicalKind(evidence.Kind)
		evidence.Namespace = strings.ToLower(strings.TrimSpace(evidence.Namespace))
		evidence.Name = strings.TrimSpace(evidence.Name)
		evidence.UID = strings.TrimSpace(evidence.UID)
		evidence.ResourceVersion = strings.TrimSpace(evidence.ResourceVersion)
		evidence.FieldPath = strings.TrimSpace(evidence.FieldPath)
		evidence.Summary = strings.TrimSpace(evidence.Summary)
		evidence.Hash = strings.TrimSpace(evidence.Hash)
		out = append(out, evidence)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return evidenceSortKey(out[i]) < evidenceSortKey(out[j])
	})
	return out
}

func normalizeSelectors(values []ResourceSelector) []ResourceSelector {
	out := make([]ResourceSelector, 0, len(values))
	for _, selector := range values {
		out = append(out, ResourceSelector{
			Namespace:     strings.ToLower(strings.TrimSpace(selector.Namespace)),
			Kind:          canonicalKind(selector.Kind),
			Name:          strings.TrimSpace(selector.Name),
			LabelSelector: strings.TrimSpace(selector.LabelSelector),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return selectorSortKey(out[i]) < selectorSortKey(out[j])
	})
	return out
}

func normalizeList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func canonicalKind(kind string) string {
	trimmed := strings.TrimSpace(kind)
	switch strings.ToLower(trimmed) {
	case "pod", "pods":
		return "Pod"
	case "deployment", "deployments":
		return "Deployment"
	case "statefulset", "statefulsets":
		return "StatefulSet"
	case "daemonset", "daemonsets":
		return "DaemonSet"
	case "replicaset", "replicasets":
		return "ReplicaSet"
	case "job", "jobs":
		return "Job"
	case "cronjob", "cronjobs":
		return "CronJob"
	case "node", "nodes":
		return "Node"
	case "service", "services":
		return "Service"
	default:
		return trimmed
	}
}

func slug(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = slugSeparatorRegex.ReplaceAllString(normalized, "-")
	normalized = strings.Trim(normalized, "-")
	if len(normalized) > MaxIdentifierBytes {
		normalized = strings.Trim(normalized[:MaxIdentifierBytes], "-")
	}
	return normalized
}
