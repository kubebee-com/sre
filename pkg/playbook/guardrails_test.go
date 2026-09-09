package playbook

import (
	"errors"
	"reflect"
	"testing"

	"github.com/kubebee-com/sre/pkg/triage"
)

func TestGuardrailsRejectUnknownAndUnsafeActions(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.ID = "unsafe"
	playbook.Steps = []NormalizedStep{{
		ID:             "one",
		Action:         "kubectl exec",
		Command:        "rm -rf /",
		EvidenceRefs:   []string{"ev-1"},
		Preconditions:  []string{"uid matches"},
		Postconditions: []string{"manual review"},
		Confidence:     0.95,
	}}

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("unsafe playbook was allowed")
	}
	want := []string{"unsafe_command", "unknown_action"}
	if !reflect.DeepEqual(decision.Reasons, want) {
		t.Fatalf("reasons = %#v, want %#v", decision.Reasons, want)
	}
}

func TestGuardrailsRejectMissingEvidencePreconditionsPostconditionsLowConfidenceAndExcessiveSteps(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Evidence = nil
	playbook.Preconditions = nil
	playbook.Postconditions = nil
	playbook.Confidence = 0.2
	playbook.Steps = append(playbook.Steps,
		NormalizedStep{ID: "two", Action: "Manual", EvidenceRefs: []string{"ev-1"}, Preconditions: []string{"uid matches"}, Postconditions: []string{"reviewed"}, Confidence: 0.95},
		NormalizedStep{ID: "three", Action: "Manual", EvidenceRefs: []string{"ev-1"}, Preconditions: []string{"uid matches"}, Postconditions: []string{"reviewed"}, Confidence: 0.95},
	)

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7, MaxSteps: 2}, playbook)
	if decision.Allowed {
		t.Fatal("invalid playbook was allowed")
	}
	want := []string{"confidence_below_minimum", "missing_evidence", "missing_postconditions", "missing_preconditions", "too_many_steps", "unknown_step_evidence"}
	if !reflect.DeepEqual(decision.Reasons, want) {
		t.Fatalf("reasons = %#v, want %#v", decision.Reasons, want)
	}
}

func TestGuardrailsFailClosedWhenPlaybookValidationFails(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Title = ""

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("invalid playbook validation result was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"invalid_playbook"}) {
		t.Fatalf("reasons = %#v", decision.Reasons)
	}
	if len(decision.Actions) != 0 {
		t.Fatalf("invalid playbook exposed mapped actions: %#v", decision.Actions)
	}
}

func TestGuardrailsPreserveIdentifierAndLifecycleClassificationForValidationFailures(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.ID = "unsafe/id"
	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("invalid identifier was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"invalid_identifier"}) {
		t.Fatalf("identifier reasons = %#v", decision.Reasons)
	}

	playbook = validGuardedPlaybook()
	playbook.Lifecycle = LifecycleState("DRAFT")
	decision = EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("invalid lifecycle was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"invalid_lifecycle"}) {
		t.Fatalf("lifecycle reasons = %#v", decision.Reasons)
	}
}

func TestGuardrailsIncludeNestedValidationClassificationsWithOtherReasons(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Steps[0].ID = "unsafe/id"
	playbook.Steps[0].Command = "kubectl exec api"

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	want := []string{"invalid_identifier", "unsafe_command"}
	if !reflect.DeepEqual(decision.Reasons, want) {
		t.Fatalf("nested identifier reasons = %#v, want %#v", decision.Reasons, want)
	}

	playbook = validGuardedPlaybook()
	playbook.Lifecycle = LifecycleState("DRAFT")
	playbook.Steps[0].Command = "kubectl exec api"
	decision = EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	want = []string{"invalid_lifecycle", "unsafe_command"}
	if !reflect.DeepEqual(decision.Reasons, want) {
		t.Fatalf("lifecycle reasons = %#v, want %#v", decision.Reasons, want)
	}

	playbook.Steps[0].ID = "unsafe/id"
	decision = EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	want = []string{"invalid_identifier", "invalid_lifecycle", "unsafe_command"}
	if !reflect.DeepEqual(decision.Reasons, want) {
		t.Fatalf("combined validation reasons = %#v, want %#v", decision.Reasons, want)
	}

	playbook = validGuardedPlaybook()
	playbook.SourceIDs = []string{"source-1", "source-1", "unsafe/id"}
	playbook.Steps[0].Command = "kubectl exec api"
	decision = EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	want = []string{"invalid_playbook", "invalid_identifier", "unsafe_command"}
	if !reflect.DeepEqual(decision.Reasons, want) {
		t.Fatalf("duplicate and nested identifier reasons = %#v, want %#v", decision.Reasons, want)
	}
}

func TestGuardrailsRequireApprovalButNotConcreteTargetForGitOps(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Steps[0].Action = "GitOpsPR"
	playbook.Steps[0].Targets = nil

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if !decision.Allowed {
		t.Fatalf("GitOps playbook was rejected: %#v", decision.Reasons)
	}
	if !decision.RequiresApproval {
		t.Fatal("GitOps playbook did not require approval")
	}
	want := []triage.ActionType{triage.ActionGitOpsPR}
	if !reflect.DeepEqual(decision.Actions, want) {
		t.Fatalf("actions = %#v, want %#v", decision.Actions, want)
	}
}

func TestGuardrailsRejectRejectedAndRetiredLifecycleForExecution(t *testing.T) {
	for _, state := range []LifecycleState{LifecycleRejected, LifecycleRetired} {
		playbook := validGuardedPlaybook()
		playbook.Lifecycle = state

		decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
		if decision.Allowed {
			t.Fatalf("terminal lifecycle %q was allowed", state)
		}
		if !reflect.DeepEqual(decision.Reasons, []string{"non_executable_lifecycle"}) {
			t.Fatalf("reasons for %q = %#v", state, decision.Reasons)
		}
	}
}

func TestGuardrailsDoNotMaskDuplicateEvidenceOrStepIDs(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Evidence = append(playbook.Evidence, EvidenceRef{ID: "ev-1", Kind: "Event", Namespace: "default", Name: "api"})

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("duplicate evidence IDs were allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"invalid_playbook"}) {
		t.Fatalf("duplicate evidence reasons = %#v", decision.Reasons)
	}

	playbook = validGuardedPlaybook()
	playbook.Steps = append(playbook.Steps, playbook.Steps[0])
	decision = EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("duplicate step IDs were allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"invalid_playbook"}) {
		t.Fatalf("duplicate step reasons = %#v", decision.Reasons)
	}
}

func TestGuardrailsRejectInvalidAndBelowPolicyStepConfidence(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Steps[0].Confidence = 0.2

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("below-policy step confidence was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"step_confidence_below_minimum"}) {
		t.Fatalf("reasons = %#v", decision.Reasons)
	}

	playbook = validGuardedPlaybook()
	playbook.Steps[0].Confidence = -0.1
	decision = EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("invalid step confidence was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"step_confidence_invalid"}) {
		t.Fatalf("reasons = %#v", decision.Reasons)
	}
}

func TestGuardrailsRejectUnknownStepEvidenceRefs(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Steps[0].EvidenceRefs = []string{"missing"}

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("unknown step evidence ref was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"unknown_step_evidence"}) {
		t.Fatalf("reasons = %#v", decision.Reasons)
	}
}

func TestGuardrailsRejectMutatingStepsWithoutConcreteTargets(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Steps[0].Targets = nil

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("mutating step without a target was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"missing_mutation_target"}) {
		t.Fatalf("reasons = %#v", decision.Reasons)
	}

	playbook = validGuardedPlaybook()
	playbook.Steps[0].Targets = []ResourceSelector{{Namespace: "default", Kind: "Pod"}}
	decision = EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("mutating step without a concrete target reference was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"missing_mutation_target"}) {
		t.Fatalf("reasons = %#v", decision.Reasons)
	}

	playbook = validGuardedPlaybook()
	playbook.Steps[0].Targets = []ResourceSelector{{Namespace: "default", Kind: "Pod", LabelSelector: "app=api"}}
	decision = EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if decision.Allowed {
		t.Fatal("mutating step with only a selector was allowed")
	}
	if !reflect.DeepEqual(decision.Reasons, []string{"missing_mutation_target"}) {
		t.Fatalf("reasons = %#v", decision.Reasons)
	}
}

func TestGuardrailsRequireActionScopedConcreteTargets(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		target  ResourceSelector
		wantErr bool
	}{
		{
			name:    "pod mutation requires namespace",
			action:  "DeleteFailedPod",
			target:  ResourceSelector{Kind: "Pod", Name: "api"},
			wantErr: true,
		},
		{
			name:    "workload mutation requires namespace",
			action:  "RolloutRestart",
			target:  ResourceSelector{Kind: "Deployment", Name: "api"},
			wantErr: true,
		},
		{
			name:    "node cordon accepts cluster scope",
			action:  "CordonNode",
			target:  ResourceSelector{Kind: "Node", Name: "worker-1"},
			wantErr: false,
		},
		{
			name:    "node cordon rejects namespace",
			action:  "CordonNode",
			target:  ResourceSelector{Namespace: "default", Kind: "Node", Name: "worker-1"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			playbook := validGuardedPlaybook()
			playbook.Steps[0].Action = tc.action
			if tc.action == "ScaleWorkload" {
				replicas := int32(3)
				playbook.Steps[0].TargetReplicas = &replicas
			}
			playbook.Steps[0].Targets = []ResourceSelector{tc.target}

			decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7, AllowClusterScoped: true}, playbook)
			if tc.wantErr {
				if decision.Allowed || !reflect.DeepEqual(decision.Reasons, []string{"missing_mutation_target"}) {
					t.Fatalf("decision = %#v, want missing mutation target", decision)
				}
				return
			}
			if !decision.Allowed {
				t.Fatalf("valid scoped target rejected: %#v", decision.Reasons)
			}
		})
	}
}

func TestGuardrailsEnforceActionKindCompatibility(t *testing.T) {
	tests := []struct {
		name      string
		action    string
		kind      string
		namespace string
		allowed   bool
	}{
		{name: "restart pod", action: "RestartPod", kind: "Pod", namespace: "default", allowed: true},
		{name: "restart deployment", action: "RestartPod", kind: "Deployment", namespace: "default"},
		{name: "delete pod", action: "DeleteFailedPod", kind: "Pod", namespace: "default", allowed: true},
		{name: "delete statefulset", action: "DeleteFailedPod", kind: "StatefulSet", namespace: "default"},
		{name: "cleanup pod", action: "CleanupPods", kind: "Pod", namespace: "default", allowed: true},
		{name: "cleanup deployment", action: "CleanupPods", kind: "Deployment", namespace: "default"},
		{name: "rollout deployment", action: "RolloutRestart", kind: "Deployment", namespace: "default", allowed: true},
		{name: "rollout statefulset", action: "RolloutRestart", kind: "StatefulSet", namespace: "default"},
		{name: "scale deployment", action: "ScaleWorkload", kind: "Deployment", namespace: "default", allowed: true},
		{name: "scale statefulset", action: "ScaleWorkload", kind: "StatefulSet", namespace: "default", allowed: true},
		{name: "scale replicaset", action: "ScaleWorkload", kind: "ReplicaSet", namespace: "default", allowed: true},
		{name: "scale pod", action: "ScaleWorkload", kind: "Pod", namespace: "default"},
		{name: "cordon node", action: "CordonNode", kind: "Node", allowed: true},
		{name: "cordon pod", action: "CordonNode", kind: "Pod"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			playbook := validGuardedPlaybook()
			playbook.Steps[0].Action = tc.action
			if tc.action == "ScaleWorkload" {
				replicas := int32(3)
				playbook.Steps[0].TargetReplicas = &replicas
			}
			playbook.Steps[0].Targets = []ResourceSelector{{Namespace: tc.namespace, Kind: tc.kind, Name: "target-1"}}

			decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7, AllowClusterScoped: true}, playbook)
			if tc.allowed && !decision.Allowed {
				t.Fatalf("compatible action target rejected: %#v", decision.Reasons)
			}
			if !tc.allowed && (decision.Allowed || !reflect.DeepEqual(decision.Reasons, []string{"missing_mutation_target"})) {
				t.Fatalf("incompatible action target decision = %#v", decision)
			}
		})
	}
}

func TestGuardrailsRejectWildcardAndOutOfScopeSelectors(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Steps[0].Targets = []ResourceSelector{
		{Namespace: "*", Kind: "Pod", Name: "api"},
		{Namespace: "prod", Kind: "Deployment", Name: "api"},
	}

	decision := EvaluateGuardrails(GuardrailPolicy{
		MinConfidence:     0.7,
		AllowedNamespaces: []string{"default"},
		AllowedKinds:      []string{"Pod"},
	}, playbook)
	if decision.Allowed {
		t.Fatal("out-of-scope playbook was allowed")
	}
	want := []string{"invalid_identifier", "missing_mutation_target", "out_of_scope_kind", "out_of_scope_namespace", "wildcard_target"}
	if !reflect.DeepEqual(decision.Reasons, want) {
		t.Fatalf("reasons = %#v, want %#v", decision.Reasons, want)
	}
}

func TestGuardrailsMapKnownMutationActionsAndRequireApproval(t *testing.T) {
	playbook := validGuardedPlaybook()

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if !decision.Allowed {
		t.Fatalf("playbook was rejected: %#v", decision.Reasons)
	}
	if !decision.RequiresApproval {
		t.Fatal("mutation action did not require approval")
	}
	want := []triage.ActionType{triage.ActionRestartPod}
	if !reflect.DeepEqual(decision.Actions, want) {
		t.Fatalf("actions = %#v, want %#v", decision.Actions, want)
	}
}

func TestGuardrailsPreserveManualObserveOnlyBehavior(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Steps = []NormalizedStep{{
		ID:             "manual",
		Action:         "Manual",
		ObserveOnly:    true,
		EvidenceRefs:   []string{"ev-1"},
		Preconditions:  []string{"uid matches"},
		Postconditions: []string{"operator reviewed"},
		Confidence:     0.95,
	}}

	decision := EvaluateGuardrails(GuardrailPolicy{MinConfidence: 0.7}, playbook)
	if !decision.Allowed {
		t.Fatalf("manual observe-only playbook was rejected: %#v", decision.Reasons)
	}
	if decision.RequiresApproval {
		t.Fatal("manual observe-only step should not require approval")
	}
}

func validGuardedPlaybook() NormalizedPlaybook {
	return NormalizedPlaybook{
		ID:                "pod-crash",
		Version:           1,
		Lifecycle:         LifecycleNormalized,
		Title:             "Pod crash",
		Summary:           "Restart pod after checks.",
		FailureCategories: []string{"PodCrashLooping"},
		TriggerConditions: []string{"restart count increased"},
		Evidence:          []EvidenceRef{{ID: "ev-1", Kind: "Pod", Namespace: "default", Name: "api", Summary: "CrashLoopBackOff"}},
		Steps: []NormalizedStep{{
			ID:             "restart",
			Action:         "RestartPod",
			Targets:        []ResourceSelector{{Namespace: "default", Kind: "Pod", Name: "api"}},
			EvidenceRefs:   []string{"ev-1"},
			Preconditions:  []string{"uid matches"},
			Postconditions: []string{"pod ready"},
			Confidence:     0.95,
		}},
		Preconditions:  []string{"uid matches"},
		Postconditions: []string{"pod ready"},
		Confidence:     0.95,
	}
}

func TestGuardrailsClusterScopeFlagIndependentOfNamespaceAllowlist(t *testing.T) {
	for _, namespaces := range [][]string{nil, {"default"}} {
		for _, allow := range []bool{false, true} {
			playbook := validGuardedPlaybook()
			playbook.Steps[0].Action = "CordonNode"
			playbook.Steps[0].Targets = []ResourceSelector{{Kind: "Node", Name: "worker-1"}}
			decision := EvaluateGuardrails(GuardrailPolicy{AllowedNamespaces: namespaces, AllowClusterScoped: allow}, playbook)
			if decision.Allowed != allow {
				t.Fatalf("namespaces=%v allow=%v: decision=%+v", namespaces, allow, decision)
			}
			if !allow && len(decision.Actions) != 0 {
				t.Fatal("rejected cluster mutation exposes actions")
			}
		}
	}
	playbook := validGuardedPlaybook()
	playbook.Steps[0].Action = "Manual"
	playbook.Steps[0].Targets = []ResourceSelector{{}}
	decision := EvaluateGuardrails(GuardrailPolicy{AllowedNamespaces: []string{"default"}}, playbook)
	if !decision.Allowed {
		t.Fatalf("unspecified manual selector treated as cluster object: %+v", decision)
	}
}

func TestObserveOnlyStepsRejectExecutableActions(t *testing.T) {
	for action := range knownActions {
		t.Run(action, func(t *testing.T) {
			target := ResourceSelector{Namespace: "default", Kind: "Pod", Name: "api"}
			switch action {
			case "RolloutRestart", "ScaleWorkload":
				target.Kind = "Deployment"
			case "CordonNode":
				target.Kind = "Node"
				target.Namespace = ""
			}
			playbook := validGuardedPlaybook()
			playbook.Steps[0].Action = action
			if action == "ScaleWorkload" {
				replicas := int32(3)
				playbook.Steps[0].TargetReplicas = &replicas
			}
			playbook.Steps[0].Targets = []ResourceSelector{target}
			playbook.Steps[0].ObserveOnly = true
			decision := EvaluateGuardrails(GuardrailPolicy{AllowClusterScoped: true}, playbook)
			plan := validResolutionPlanForValidation()
			plan.Steps = playbook.Steps
			plan.Target = target
			plan.RequiresApproval = true
			if action == "Manual" {
				if !decision.Allowed {
					t.Fatalf("manual observation rejected: %+v", decision)
				}
				if err := plan.Validate(); err != nil {
					t.Fatalf("manual observation rejected: %v", err)
				}
				return
			}
			if decision.Allowed || len(decision.Actions) != 0 {
				t.Errorf("observe-only step exposes execution: %+v", decision)
			}
			if err := plan.Validate(); !errors.Is(err, ErrObserveOnlyMutation) {
				t.Errorf("observe-only mutation error = %v", err)
			}
		})
	}
}
