package playbook

import (
	"errors"
	"math"
	"sort"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/triage"
)

const (
	DefaultMaxGuardrailSteps = 20
	MaxGuardrailReasons      = 32
)

type GuardrailPolicy struct {
	MinConfidence      float64  `json:"min_confidence,omitempty"`
	MaxSteps           int      `json:"max_steps,omitempty"`
	AllowedNamespaces  []string `json:"allowed_namespaces,omitempty"`
	AllowedKinds       []string `json:"allowed_kinds,omitempty"`
	AllowClusterScoped bool     `json:"allow_cluster_scoped,omitempty"`
}

type GuardrailDecision struct {
	Allowed          bool                `json:"allowed"`
	RequiresApproval bool                `json:"requires_approval"`
	Reasons          []string            `json:"reasons,omitempty"`
	Actions          []triage.ActionType `json:"actions,omitempty"`
}

var knownActions = map[string]triage.ActionType{
	string(triage.ActionRestartPod):      triage.ActionRestartPod,
	string(triage.ActionDeleteFailedPod): triage.ActionDeleteFailedPod,
	string(triage.ActionScaleWorkload):   triage.ActionScaleWorkload,
	string(triage.ActionRolloutRestart):  triage.ActionRolloutRestart,
	string(triage.ActionCordonNode):      triage.ActionCordonNode,
	string(triage.ActionCleanupPods):     triage.ActionCleanupPods,
	string(triage.ActionGitOpsPR):        triage.ActionGitOpsPR,
	string(triage.ActionManual):          triage.ActionManual,
}

var guardrailReasonOrder = []string{
	"invalid_playbook",
	"invalid_identifier",
	"invalid_lifecycle",
	"non_executable_lifecycle",
	"confidence_invalid",
	"confidence_below_minimum",
	"step_confidence_invalid",
	"step_confidence_below_minimum",
	"missing_evidence",
	"missing_postconditions",
	"missing_preconditions",
	"missing_steps",
	"too_many_steps",
	"unsafe_command",
	"unknown_action",
	"unknown_step_evidence",
	"missing_step_evidence",
	"missing_step_postconditions",
	"missing_step_preconditions",
	"missing_mutation_target",
	"out_of_scope_kind",
	"out_of_scope_namespace",
	"wildcard_target",
}

func EvaluateGuardrails(policy GuardrailPolicy, playbook NormalizedPlaybook) GuardrailDecision {
	validationErr := playbook.Validate()

	reasons := map[string]struct{}{}
	actions := make([]triage.ActionType, 0, len(playbook.Steps))
	requiresApproval := false

	addReason := func(reason string) {
		reasons[reason] = struct{}{}
	}

	if playbookHasInvalidIdentifier(playbook) {
		addReason("invalid_identifier")
	}
	if err := playbook.Lifecycle.Validate(); err != nil {
		addReason("invalid_lifecycle")
	}
	if playbook.Lifecycle == LifecycleRejected || playbook.Lifecycle == LifecycleRetired {
		addReason("non_executable_lifecycle")
	}
	if invalidConfidence(playbook.Confidence) {
		addReason("confidence_invalid")
	} else if policy.MinConfidence > 0 && playbook.Confidence < policy.MinConfidence {
		addReason("confidence_below_minimum")
	}
	if len(playbook.Evidence) == 0 {
		addReason("missing_evidence")
	}
	if len(playbook.Postconditions) == 0 {
		addReason("missing_postconditions")
	}
	if len(playbook.Preconditions) == 0 {
		addReason("missing_preconditions")
	}
	if len(playbook.Steps) == 0 {
		addReason("missing_steps")
	}
	maxSteps := policy.MaxSteps
	if maxSteps <= 0 {
		maxSteps = DefaultMaxGuardrailSteps
	}
	if len(playbook.Steps) > maxSteps {
		addReason("too_many_steps")
	}

	evidenceIDs := make(map[string]struct{}, len(playbook.Evidence))
	for _, evidence := range playbook.Evidence {
		id := strings.TrimSpace(evidence.ID)
		if id != "" {
			evidenceIDs[id] = struct{}{}
		}
	}

	allowedNamespaces := normalizedSet(policy.AllowedNamespaces, true)
	allowedKinds := normalizedSet(policy.AllowedKinds, false)
	for _, selector := range playbook.Applicability {
		evaluateSelector(selector, allowedNamespaces, allowedKinds, policy.AllowClusterScoped, addReason)
	}
	for _, step := range playbook.Steps {
		action, ok := knownActions[strings.TrimSpace(step.Action)]
		if !ok {
			addReason("unknown_action")
		} else {
			actions = append(actions, action)
			if action == triage.ActionScaleWorkload && step.TargetReplicas == nil {
				addReason("missing_target_replicas")
			}
			if step.ObserveOnly && actionRequiresApproval(action) {
				addReason("observe_only_mutation")
			}
			if actionRequiresApproval(action) {
				requiresApproval = true
			}
			if actionRequiresConcreteTarget(action) && !hasConcreteTarget(action, step.Targets) {
				addReason("missing_mutation_target")
			}
		}
		if invalidConfidence(step.Confidence) {
			addReason("step_confidence_invalid")
		} else if policy.MinConfidence > 0 && step.Confidence < policy.MinConfidence {
			addReason("step_confidence_below_minimum")
		}
		if strings.TrimSpace(step.Command) != "" && unsafeCommand(step.Command) {
			addReason("unsafe_command")
		}
		if len(step.EvidenceRefs) == 0 {
			addReason("missing_step_evidence")
		}
		for _, evidenceRef := range step.EvidenceRefs {
			if _, ok := evidenceIDs[strings.TrimSpace(evidenceRef)]; !ok {
				addReason("unknown_step_evidence")
			}
		}
		if len(step.Postconditions) == 0 {
			addReason("missing_step_postconditions")
		}
		if len(step.Preconditions) == 0 {
			addReason("missing_step_preconditions")
		}
		for _, selector := range step.Targets {
			evaluateSelector(selector, allowedNamespaces, allowedKinds, policy.AllowClusterScoped, addReason)
		}
	}

	actions = dedupeActions(actions)
	if validationErr != nil && !errors.Is(validationErr, ErrInvalidConfidence) {
		addReason(validationGuardrailReason(validationErr))
		actions = nil
	}
	orderedReasons := orderedGuardrailReasons(reasons)
	if len(orderedReasons) > 0 {
		actions = nil
	}
	return GuardrailDecision{
		Allowed:          len(orderedReasons) == 0,
		RequiresApproval: requiresApproval,
		Reasons:          orderedReasons,
		Actions:          actions,
	}
}

func actionRequiresApproval(action triage.ActionType) bool {
	return action != triage.ActionManual
}

func actionRequiresConcreteTarget(action triage.ActionType) bool {
	switch action {
	case triage.ActionRestartPod, triage.ActionDeleteFailedPod, triage.ActionScaleWorkload,
		triage.ActionRolloutRestart, triage.ActionCordonNode, triage.ActionCleanupPods:
		return true
	default:
		return false
	}
}

func playbookHasInvalidIdentifier(playbook NormalizedPlaybook) bool {
	if requireIdentifier("playbook id", playbook.ID) != nil || playbook.Version <= 0 ||
		optionalIdentifier("playbook canonical hash", playbook.CanonicalHash) != nil {
		return true
	}
	for _, values := range [][]string{playbook.SourceIDs, playbook.Lineage} {
		for _, value := range values {
			if requireIdentifier("playbook reference", value) != nil {
				return true
			}
		}
	}
	for _, selector := range playbook.Applicability {
		if selectorHasInvalidIdentifier(selector) {
			return true
		}
	}
	for _, evidence := range playbook.Evidence {
		if requireIdentifier("evidence id", evidence.ID) != nil ||
			optionalIdentifier("evidence source id", evidence.SourceID) != nil ||
			optionalKubernetesKind("evidence kind", evidence.Kind) != nil ||
			optionalKubernetesNamespace("evidence namespace", evidence.Namespace) != nil ||
			optionalKubernetesName("evidence name", evidence.Name) != nil ||
			optionalIdentifier("evidence uid", evidence.UID) != nil ||
			optionalIdentifier("evidence resource version", evidence.ResourceVersion) != nil ||
			optionalIdentifier("evidence hash", evidence.Hash) != nil {
			return true
		}
	}
	for _, step := range playbook.Steps {
		if requireIdentifier("step id", step.ID) != nil {
			return true
		}
		for _, evidenceRef := range step.EvidenceRefs {
			if requireIdentifier("step evidence ref", evidenceRef) != nil {
				return true
			}
		}
		for _, selector := range step.Targets {
			if selectorHasInvalidIdentifier(selector) {
				return true
			}
		}
	}
	return false
}

func selectorHasInvalidIdentifier(selector ResourceSelector) bool {
	return optionalKubernetesNamespace("selector namespace", selector.Namespace) != nil ||
		optionalKubernetesKind("selector kind", selector.Kind) != nil ||
		optionalKubernetesName("selector name", selector.Name) != nil
}

func validationGuardrailReason(err error) string {
	switch {
	case errors.Is(err, ErrInvalidIdentifier):
		return "invalid_identifier"
	case errors.Is(err, ErrInvalidLifecycleState):
		return "invalid_lifecycle"
	default:
		return "invalid_playbook"
	}
}

func evaluateSelector(selector ResourceSelector, allowedNamespaces, allowedKinds map[string]struct{}, allowClusterScoped bool, addReason func(string)) {
	namespace := strings.ToLower(strings.TrimSpace(selector.Namespace))
	kind := canonicalKind(selector.Kind)
	name := strings.TrimSpace(selector.Name)
	labelSelector := strings.TrimSpace(selector.LabelSelector)

	if hasWildcard(namespace) || hasWildcard(kind) || hasWildcard(name) || hasWildcard(labelSelector) {
		addReason("wildcard_target")
	}
	if namespace == "" {
		if !allowClusterScoped && kind != "" && (name != "" || labelSelector != "") {
			addReason("out_of_scope_namespace")
		}
	} else if len(allowedNamespaces) > 0 {
		if _, ok := allowedNamespaces[namespace]; !ok {
			addReason("out_of_scope_namespace")
		}
	}
	if len(allowedKinds) > 0 {
		if _, ok := allowedKinds[kind]; !ok {
			addReason("out_of_scope_kind")
		}
	}
}

func hasConcreteTarget(action triage.ActionType, selectors []ResourceSelector) bool {
	if len(selectors) == 0 {
		return false
	}
	for _, selector := range selectors {
		if !isConcreteTargetForAction(action, selector) {
			return false
		}
	}
	return true
}

func isConcreteTargetForAction(action triage.ActionType, selector ResourceSelector) bool {
	namespace := strings.ToLower(strings.TrimSpace(selector.Namespace))
	kind := canonicalKind(selector.Kind)
	name := strings.TrimSpace(selector.Name)
	if kind == "" || name == "" || !actionSupportsKind(action, kind) {
		return false
	}
	if action == triage.ActionCordonNode {
		return namespace == ""
	}
	return namespace != ""
}

func actionSupportsKind(action triage.ActionType, kind string) bool {
	switch action {
	case triage.ActionRestartPod, triage.ActionDeleteFailedPod, triage.ActionCleanupPods:
		return kind == "Pod"
	case triage.ActionRolloutRestart:
		return kind == "Deployment"
	case triage.ActionScaleWorkload:
		return kind == "Deployment" || kind == "StatefulSet" || kind == "ReplicaSet"
	case triage.ActionCordonNode:
		return kind == "Node"
	default:
		return false
	}
}

func targetsMatchSnapshot(action triage.ActionType, targets []ResourceSelector, snapshot ResourceSelector) bool {
	if !isConcreteTargetForAction(action, snapshot) || len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if !isConcreteTargetForAction(action, target) ||
			strings.ToLower(strings.TrimSpace(target.Namespace)) != strings.ToLower(strings.TrimSpace(snapshot.Namespace)) ||
			canonicalKind(target.Kind) != canonicalKind(snapshot.Kind) ||
			strings.TrimSpace(target.Name) != strings.TrimSpace(snapshot.Name) {
			return false
		}
	}
	return true
}

func normalizedSet(values []string, lower bool) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if lower {
			trimmed = strings.ToLower(trimmed)
		} else {
			trimmed = canonicalKind(trimmed)
		}
		out[trimmed] = struct{}{}
	}
	return out
}

func hasWildcard(value string) bool {
	return strings.Contains(value, "*")
}

func unsafeCommand(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}
	if sanitizer.SanitizeText(command) != command {
		return true
	}
	return true
}

func invalidConfidence(confidence float64) bool {
	return math.IsNaN(confidence) || math.IsInf(confidence, 0) || confidence < 0 || confidence > 1
}

func orderedGuardrailReasons(reasons map[string]struct{}) []string {
	if len(reasons) == 0 {
		return nil
	}
	out := make([]string, 0, len(reasons))
	for _, reason := range guardrailReasonOrder {
		if _, ok := reasons[reason]; ok {
			out = append(out, reason)
		}
	}
	extras := make([]string, 0)
	for reason := range reasons {
		if !knownGuardrailReason(reason) {
			extras = append(extras, reason)
		}
	}
	sort.Strings(extras)
	out = append(out, extras...)
	if len(out) > MaxGuardrailReasons {
		return out[:MaxGuardrailReasons]
	}
	return out
}

func knownGuardrailReason(reason string) bool {
	for _, known := range guardrailReasonOrder {
		if reason == known {
			return true
		}
	}
	return false
}

func dedupeActions(actions []triage.ActionType) []triage.ActionType {
	if len(actions) == 0 {
		return nil
	}
	seen := make(map[triage.ActionType]struct{}, len(actions))
	out := make([]triage.ActionType, 0, len(actions))
	for _, action := range actions {
		if _, ok := seen[action]; ok {
			continue
		}
		seen[action] = struct{}{}
		out = append(out, action)
	}
	return out
}
