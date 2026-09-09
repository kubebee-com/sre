package playbook

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLifecycleStateValidation(t *testing.T) {
	valid := []LifecycleState{
		LifecycleReceived,
		LifecycleDigested,
		LifecycleNormalized,
		LifecycleReview,
		LifecycleActive,
		LifecycleRejected,
		LifecycleRetired,
	}

	for _, state := range valid {
		if err := state.Validate(); err != nil {
			t.Fatalf("state %q should be valid: %v", state, err)
		}
	}

	if err := LifecycleState("DRAFT").Validate(); !errors.Is(err, ErrInvalidLifecycleState) {
		t.Fatalf("invalid lifecycle error = %v, want %v", err, ErrInvalidLifecycleState)
	}
}

func TestSourceArtifactValidationRequiresIdentifiersAndBoundsContent(t *testing.T) {
	source := SourceArtifact{
		ID:               "src-1",
		Kind:             "markdown",
		Origin:           "operator upload",
		MediaType:        "text/markdown",
		Checksum:         "sha256:abc",
		ParserVersion:    "parser-v1",
		SanitizedContent: "inspect pod logs",
	}
	if err := source.Validate(); err != nil {
		t.Fatalf("source should be valid: %v", err)
	}

	source.ID = ""
	if err := source.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("blank ID error = %v, want %v", err, ErrInvalidIdentifier)
	}

	source.ID = "src-1"
	source.SanitizedContent = strings.Repeat("a", MaxSourceBytes+1)
	if err := source.Validate(); !errors.Is(err, ErrTextTooLong) {
		t.Fatalf("oversized content error = %v, want %v", err, ErrTextTooLong)
	}
}

func TestValidationBoundsNestedStringsSlicesAndMaps(t *testing.T) {
	oversized := strings.Repeat("a", MaxTextBytes+1)
	source := SourceArtifact{
		ID:               "src-1",
		Kind:             "markdown",
		Origin:           "operator upload",
		MediaType:        "text/markdown",
		Checksum:         "sha256:abc",
		ParserVersion:    "parser-v1",
		Provenance:       map[string]string{"safe": oversized},
		SanitizedContent: "inspect pod logs",
	}
	if err := source.Validate(); !errors.Is(err, ErrTextTooLong) {
		t.Fatalf("oversized provenance value error = %v, want %v", err, ErrTextTooLong)
	}

	digest := validDigestForValidation()
	digest.Steps[0].Targets = []ResourceSelector{{LabelSelector: oversized}}
	if err := digest.Validate(); !errors.Is(err, ErrTextTooLong) {
		t.Fatalf("oversized nested selector error = %v, want %v", err, ErrTextTooLong)
	}

	playbook := validPlaybookForValidation()
	playbook.Unknowns = []string{oversized}
	if err := playbook.Validate(); !errors.Is(err, ErrTextTooLong) {
		t.Fatalf("oversized string slice error = %v, want %v", err, ErrTextTooLong)
	}
}

func TestValidationRejectsExcessiveNestedCounts(t *testing.T) {
	source := SourceArtifact{
		ID:               "src-1",
		Kind:             "markdown",
		Origin:           "operator upload",
		MediaType:        "text/markdown",
		Checksum:         "sha256:abc",
		ParserVersion:    "parser-v1",
		Provenance:       mapWithEntries(MaxCollectionItems + 1),
		SanitizedContent: "inspect pod logs",
	}
	if err := source.Validate(); !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("excessive provenance error = %v, want %v", err, ErrTooManyItems)
	}

	playbook := validPlaybookForValidation()
	playbook.TriggerConditions = stringsWithEntries(MaxCollectionItems + 1)
	if err := playbook.Validate(); !errors.Is(err, ErrTooManyItems) {
		t.Fatalf("excessive trigger conditions error = %v, want %v", err, ErrTooManyItems)
	}
}

func TestValidationRejectsDuplicateIdentifiers(t *testing.T) {
	digest := validDigestForValidation()
	digest.Evidence = append(digest.Evidence, EvidenceRef{ID: "ev-1", Kind: "Event", Namespace: "default", Name: "api"})
	if err := digest.Validate(); !errors.Is(err, ErrDuplicateIdentifier) {
		t.Fatalf("duplicate digest evidence error = %v, want %v", err, ErrDuplicateIdentifier)
	}

	digest = validDigestForValidation()
	digest.Steps = []DigestStep{
		{ID: "step-1", Action: "Manual", EvidenceRefs: []string{"ev-1"}, Preconditions: []string{"uid matches"}, Postconditions: []string{"reviewed"}, Confidence: 0.8},
		{ID: "step-1", Action: "Manual", EvidenceRefs: []string{"ev-1"}, Preconditions: []string{"uid matches"}, Postconditions: []string{"reviewed"}, Confidence: 0.8},
	}
	if err := digest.Validate(); !errors.Is(err, ErrDuplicateIdentifier) {
		t.Fatalf("duplicate digest step error = %v, want %v", err, ErrDuplicateIdentifier)
	}

	playbook := validPlaybookForValidation()
	playbook.SourceIDs = []string{"source-1", "source-1"}
	if err := playbook.Validate(); !errors.Is(err, ErrDuplicateIdentifier) {
		t.Fatalf("duplicate playbook source ID error = %v, want %v", err, ErrDuplicateIdentifier)
	}

	playbook = validPlaybookForValidation()
	playbook.Evidence = append(playbook.Evidence, EvidenceRef{ID: "ev-1", Kind: "Event", Namespace: "default", Name: "api"})
	if err := playbook.Validate(); !errors.Is(err, ErrDuplicateIdentifier) {
		t.Fatalf("duplicate playbook evidence ID error = %v, want %v", err, ErrDuplicateIdentifier)
	}

	playbook = validPlaybookForValidation()
	playbook.Steps = append(playbook.Steps, playbook.Steps[0])
	if err := playbook.Validate(); !errors.Is(err, ErrDuplicateIdentifier) {
		t.Fatalf("duplicate playbook step ID error = %v, want %v", err, ErrDuplicateIdentifier)
	}

	playbook = validPlaybookForValidation()
	playbook.Steps[0].EvidenceRefs = []string{"ev-1", "ev-1"}
	if err := playbook.Validate(); !errors.Is(err, ErrDuplicateIdentifier) {
		t.Fatalf("duplicate step evidence ref error = %v, want %v", err, ErrDuplicateIdentifier)
	}
}

func TestPlaybookDigestValidationKeepsImportedActionNamesAsStrings(t *testing.T) {
	digest := PlaybookDigest{
		ID:                "digest-1",
		SourceID:          "source-1",
		Title:             "CrashLoopBackOff restart",
		Summary:           "Restart a crashing pod after evidence review.",
		FailureCategories: []string{"PodCrashLooping"},
		TriggerConditions: []string{"pod restart count increased"},
		Evidence:          []EvidenceRef{{ID: "ev-1", Kind: "Pod", Namespace: "default", Name: "api", Summary: "CrashLoopBackOff"}},
		Steps: []DigestStep{{
			Action:         "kubectl exec",
			Description:    "Imported arbitrary command remains a string for guardrail rejection.",
			EvidenceRefs:   []string{"ev-1"},
			Preconditions:  []string{"target UID still matches"},
			Postconditions: []string{"operator verifies state"},
			Confidence:     0.8,
		}},
		Preconditions:  []string{"target UID still matches"},
		Postconditions: []string{"pod becomes Ready"},
		Confidence:     0.8,
	}

	if err := digest.Validate(); err != nil {
		t.Fatalf("digest should be valid before action mapping: %v", err)
	}
	if digest.Steps[0].Action != "kubectl exec" {
		t.Fatalf("digest action was coerced to %q", digest.Steps[0].Action)
	}

	digest.Confidence = 1.01
	if err := digest.Validate(); !errors.Is(err, ErrInvalidConfidence) {
		t.Fatalf("invalid confidence error = %v, want %v", err, ErrInvalidConfidence)
	}
}

func TestValidationUsesIdentifierErrorsForIdentifierFields(t *testing.T) {
	digest := validDigestForValidation()
	digest.ID = strings.Repeat("x", MaxIdentifierBytes+1)
	if err := digest.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("digest ID error = %v, want %v", err, ErrInvalidIdentifier)
	}

	plan := validResolutionPlanForValidation()
	plan.TargetUID = strings.Repeat("x", MaxIdentifierBytes+1)
	if err := plan.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("resolution target UID error = %v, want %v", err, ErrInvalidIdentifier)
	}

	candidate := validLearningCandidateForValidation()
	candidate.IdempotencyKey = strings.Repeat("x", MaxIdentifierBytes+1)
	if err := candidate.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("learning idempotency key error = %v, want %v", err, ErrInvalidIdentifier)
	}

	playbook := validPlaybookForValidation()
	playbook.SourceIDs = []string{strings.Repeat("x", MaxIdentifierBytes+1)}
	if err := playbook.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("playbook source ID error = %v, want %v", err, ErrInvalidIdentifier)
	}
}

func TestIdentifierValidationRejectsUnsafeText(t *testing.T) {
	invalid := []string{
		"source 1",
		"source\t1",
		"source\n1",
		"../source",
		`source\name`,
		"source;rm",
		"source$HOME",
		"source|next",
		"source`date`",
		"source,1",
		"source☃",
	}
	for _, value := range invalid {
		source := SourceArtifact{
			ID:               value,
			Kind:             "markdown",
			Origin:           "operator upload",
			MediaType:        "text/markdown",
			Checksum:         "sha256:abc",
			ParserVersion:    "parser-v1",
			SanitizedContent: "inspect pod logs",
		}
		if err := source.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
			t.Fatalf("source ID %q error = %v, want %v", value, err, ErrInvalidIdentifier)
		}
	}

	playbook := validPlaybookForValidation()
	playbook.ID = "pod-crash_1.2:3"
	playbook.SourceIDs = []string{"source-1"}
	playbook.Steps[0].ID = "step_001"
	playbook.Evidence[0].ID = "ev.1"
	playbook.Evidence[0].UID = "123e4567-e89b-12d3-a456-426614174000"
	playbook.Evidence[0].ResourceVersion = "987654"
	playbook.Evidence[0].Hash = "sha256:abcdef"
	if err := playbook.Validate(); err != nil {
		t.Fatalf("valid identifier forms should pass: %v", err)
	}

	playbook = validPlaybookForValidation()
	playbook.Steps[0].Targets = []ResourceSelector{{Namespace: "default", Kind: "Pod", Name: "api/pod"}}
	if err := playbook.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("unsafe selector name error = %v, want %v", err, ErrInvalidIdentifier)
	}
}

func TestEvidenceAndMatchQueryValidateResourceIdentifiers(t *testing.T) {
	evidence := EvidenceRef{ID: "ev-1", Kind: "Node", Name: "worker-1"}
	if err := evidence.Validate(); err != nil {
		t.Fatalf("cluster-scoped evidence rejected: %v", err)
	}

	evidenceCases := []struct {
		name string
		edit func(*EvidenceRef)
	}{
		{name: "kind", edit: func(ref *EvidenceRef) { ref.Kind = "Pod;rm" }},
		{name: "namespace", edit: func(ref *EvidenceRef) { ref.Namespace = "bad/ns" }},
		{name: "name", edit: func(ref *EvidenceRef) { ref.Name = "api\nnext" }},
	}
	for _, tc := range evidenceCases {
		t.Run("evidence "+tc.name, func(t *testing.T) {
			ref := EvidenceRef{ID: "ev-1"}
			tc.edit(&ref)
			if err := ref.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
				t.Fatalf("unsafe evidence %s error = %v, want %v", tc.name, err, ErrInvalidIdentifier)
			}
		})
	}

	query := MatchQuery{Kind: "Node", Name: "worker-1"}
	if err := query.Validate(); err != nil {
		t.Fatalf("cluster-scoped match query rejected: %v", err)
	}

	queryCases := []struct {
		name string
		edit func(*MatchQuery)
	}{
		{name: "namespace", edit: func(query *MatchQuery) { query.Namespace = "bad namespace" }},
		{name: "kind", edit: func(query *MatchQuery) { query.Kind = "Pod|next" }},
		{name: "name", edit: func(query *MatchQuery) { query.Name = "../api" }},
	}
	for _, tc := range queryCases {
		t.Run("query "+tc.name, func(t *testing.T) {
			query := MatchQuery{}
			tc.edit(&query)
			if err := query.Validate(); !errors.Is(err, ErrInvalidIdentifier) {
				t.Fatalf("unsafe query %s error = %v, want %v", tc.name, err, ErrInvalidIdentifier)
			}
		})
	}
}

func TestKubernetesResourceCoordinatesUseNativeValidation(t *testing.T) {
	type coordinates struct {
		namespace string
		kind      string
		name      string
	}
	tests := []struct {
		name  string
		value coordinates
		valid bool
	}{
		{name: "namespaced built-in", value: coordinates{namespace: "team-a", kind: "Pod", name: "api.v1"}, valid: true},
		{name: "known lowercase kind", value: coordinates{namespace: "default", kind: "pod", name: "api"}, valid: true},
		{name: "custom kind", value: coordinates{namespace: "default", kind: "Widget", name: "widget-1"}, valid: true},
		{name: "cluster scoped", value: coordinates{kind: "Node", name: "worker.example.com"}, valid: true},
		{name: "uppercase namespace", value: coordinates{namespace: "Default", kind: "Pod", name: "api"}},
		{name: "uppercase name", value: coordinates{namespace: "default", kind: "Pod", name: "API"}},
		{name: "colon name", value: coordinates{namespace: "default", kind: "Pod", name: "api:v1"}},
		{name: "namespace is not DNS label", value: coordinates{namespace: "team.prod", kind: "Pod", name: "api"}},
		{name: "name is not DNS subdomain", value: coordinates{namespace: "default", kind: "Pod", name: "api_service"}},
		{name: "kind punctuation", value: coordinates{namespace: "default", kind: "Pod.Workload", name: "api"}},
		{name: "unknown lowercase kind", value: coordinates{namespace: "default", kind: "widget", name: "api"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			selector := ResourceSelector{Namespace: tc.value.namespace, Kind: tc.value.kind, Name: tc.value.name}
			evidence := EvidenceRef{ID: "ev-1", Namespace: tc.value.namespace, Kind: tc.value.kind, Name: tc.value.name}
			query := MatchQuery{Namespace: tc.value.namespace, Kind: tc.value.kind, Name: tc.value.name}

			for name, err := range map[string]error{
				"selector": selector.Validate(),
				"evidence": evidence.Validate(),
				"query":    query.Validate(),
			} {
				if tc.valid && err != nil {
					t.Fatalf("valid %s coordinates rejected: %v", name, err)
				}
				if !tc.valid && !errors.Is(err, ErrInvalidIdentifier) {
					t.Fatalf("invalid %s coordinates error = %v, want %v", name, err, ErrInvalidIdentifier)
				}
			}
		})
	}
}

func TestResourceSelectorValidationRequiresNarrowKubernetesSelectors(t *testing.T) {
	valid := []string{
		"",
		"app=api",
		"app.kubernetes.io/name=api",
		"environment in (prod,staging),tier=backend",
	}
	for _, value := range valid {
		selector := ResourceSelector{Namespace: "default", Kind: "Pod", Name: "api", LabelSelector: value}
		if err := selector.Validate(); err != nil {
			t.Fatalf("valid label selector %q rejected: %v", value, err)
		}
	}

	invalid := []string{
		"app in (",
		"app",
		"!app",
		"app!=api",
		"app notin (api)",
		"app=api\nteam=sre",
		"app=api;rm",
		"*",
		"app=*",
	}
	for _, value := range invalid {
		selector := ResourceSelector{Namespace: "default", Kind: "Pod", Name: "api", LabelSelector: value}
		if err := selector.Validate(); !errors.Is(err, ErrInvalidLabelSelector) {
			t.Fatalf("invalid label selector %q error = %v, want %v", value, err, ErrInvalidLabelSelector)
		}
	}
}

func TestResolutionPlanValidationFailsClosedForUnsafeSteps(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ResolutionPlan)
		want error
	}{
		{
			name: "unresolved evidence ref",
			edit: func(plan *ResolutionPlan) {
				plan.Steps[0].EvidenceRefs = []string{"missing"}
			},
			want: ErrUnresolvedReference,
		},
		{
			name: "missing step preconditions",
			edit: func(plan *ResolutionPlan) {
				plan.Steps[0].Preconditions = nil
			},
			want: ErrMissingRequired,
		},
		{
			name: "missing step postconditions",
			edit: func(plan *ResolutionPlan) {
				plan.Steps[0].Postconditions = nil
			},
			want: ErrMissingRequired,
		},
		{
			name: "missing verification criteria",
			edit: func(plan *ResolutionPlan) {
				plan.Verification = nil
			},
			want: ErrMissingRequired,
		},
		{
			name: "arbitrary command",
			edit: func(plan *ResolutionPlan) {
				plan.Steps[0].Command = "kubectl exec api -- rm -rf /"
			},
			want: ErrUnsafeCommand,
		},
		{
			name: "unknown action",
			edit: func(plan *ResolutionPlan) {
				plan.Steps[0].Action = "kubectl exec"
			},
			want: ErrUnknownAction,
		},
		{
			name: "mutating action without concrete target",
			edit: func(plan *ResolutionPlan) {
				plan.Steps[0].Action = "RestartPod"
				plan.Steps[0].Targets = []ResourceSelector{{Namespace: "default", Kind: "Pod"}}
			},
			want: ErrMissingRequired,
		},
		{
			name: "mutating action with selector but no target name",
			edit: func(plan *ResolutionPlan) {
				plan.Steps[0].Action = "RestartPod"
				plan.Steps[0].Targets = []ResourceSelector{{Namespace: "default", Kind: "Pod", LabelSelector: "app=api"}}
			},
			want: ErrMissingRequired,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := validResolutionPlanForValidation()
			tc.edit(&plan)
			if err := plan.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("resolution validation error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestResolutionPlanRequiresApprovalForNonManualActions(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		targets []ResourceSelector
	}{
		{
			name:    "direct mutation",
			action:  "RestartPod",
			targets: []ResourceSelector{{Namespace: "default", Kind: "Pod", Name: "api"}},
		},
		{
			name:   "GitOps proposal",
			action: "GitOpsPR",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := validResolutionPlanForValidation()
			plan.Steps[0].Action = tc.action
			if tc.action == "ScaleWorkload" {
				replicas := int32(3)
				plan.Steps[0].TargetReplicas = &replicas
			}
			plan.Steps[0].Targets = tc.targets
			plan.RequiresApproval = false
			if err := plan.Validate(); !errors.Is(err, ErrMissingRequired) {
				t.Fatalf("unapproved %s error = %v, want %v", tc.action, err, ErrMissingRequired)
			}

			plan.RequiresApproval = true
			if err := plan.Validate(); err != nil {
				t.Fatalf("approved %s plan rejected: %v", tc.action, err)
			}
		})
	}

	plan := validResolutionPlanForValidation()
	plan.Steps[0].Action = "Manual"
	plan.Steps[0].Targets = nil
	plan.RequiresApproval = false
	if err := plan.Validate(); err != nil {
		t.Fatalf("manual plan without approval rejected: %v", err)
	}
}

func TestResolutionPlanRequiresActionScopedConcreteTargets(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		target  ResourceSelector
		wantErr bool
	}{
		{
			name:    "pod mutation requires namespace",
			action:  "RestartPod",
			target:  ResourceSelector{Kind: "Pod", Name: "api"},
			wantErr: true,
		},
		{
			name:    "workload mutation requires namespace",
			action:  "ScaleWorkload",
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
			plan := validResolutionPlanForValidation()
			plan.Target = tc.target
			plan.Steps[0].Action = tc.action
			if tc.action == "ScaleWorkload" {
				replicas := int32(3)
				plan.Steps[0].TargetReplicas = &replicas
			}
			plan.Steps[0].Targets = []ResourceSelector{tc.target}
			plan.RequiresApproval = true

			err := plan.Validate()
			if tc.wantErr && !errors.Is(err, ErrMissingRequired) {
				t.Fatalf("resolution validation error = %v, want %v", err, ErrMissingRequired)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("valid scoped target rejected: %v", err)
			}
		})
	}
}

func TestResolutionPlanEnforcesActionKindCompatibility(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		target  ResourceSelector
		wantErr bool
	}{
		{name: "pod action", action: "RestartPod", target: ResourceSelector{Namespace: "default", Kind: "Pod", Name: "api"}},
		{name: "pod action wrong kind", action: "RestartPod", target: ResourceSelector{Namespace: "default", Kind: "Deployment", Name: "api"}, wantErr: true},
		{name: "rollout deployment", action: "RolloutRestart", target: ResourceSelector{Namespace: "default", Kind: "Deployment", Name: "api"}},
		{name: "rollout wrong kind", action: "RolloutRestart", target: ResourceSelector{Namespace: "default", Kind: "StatefulSet", Name: "api"}, wantErr: true},
		{name: "scale replicaset", action: "ScaleWorkload", target: ResourceSelector{Namespace: "default", Kind: "ReplicaSet", Name: "api"}},
		{name: "scale wrong kind", action: "ScaleWorkload", target: ResourceSelector{Namespace: "default", Kind: "Pod", Name: "api"}, wantErr: true},
		{name: "cordon node", action: "CordonNode", target: ResourceSelector{Kind: "Node", Name: "worker-1"}},
		{name: "cordon wrong kind", action: "CordonNode", target: ResourceSelector{Kind: "Pod", Name: "worker-1"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := validResolutionPlanForValidation()
			plan.Target = tc.target
			plan.Steps[0].Action = tc.action
			if tc.action == "ScaleWorkload" {
				replicas := int32(3)
				plan.Steps[0].TargetReplicas = &replicas
			}
			plan.Steps[0].Targets = []ResourceSelector{tc.target}
			plan.RequiresApproval = true

			err := plan.Validate()
			if tc.wantErr && !errors.Is(err, ErrMissingRequired) {
				t.Fatalf("incompatible target error = %v, want %v", err, ErrMissingRequired)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("compatible target rejected: %v", err)
			}
		})
	}
}

func TestResolutionPlanRejectsTargetsOutsideSnapshot(t *testing.T) {
	tests := []struct {
		name   string
		action string
		target ResourceSelector
		extra  *ResourceSelector
	}{
		{
			name:   "namespace mismatch",
			action: "RestartPod",
			target: ResourceSelector{Namespace: "other", Kind: "Pod", Name: "api"},
		},
		{
			name:   "name mismatch",
			action: "RestartPod",
			target: ResourceSelector{Namespace: "default", Kind: "Pod", Name: "other"},
		},
		{
			name:   "compatible kind mismatch",
			action: "ScaleWorkload",
			target: ResourceSelector{Namespace: "default", Kind: "StatefulSet", Name: "api"},
		},
		{
			name:   "additional target",
			action: "RestartPod",
			target: ResourceSelector{Namespace: "default", Kind: "Pod", Name: "api"},
			extra:  &ResourceSelector{Namespace: "default", Kind: "Pod", Name: "other"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := validResolutionPlanForValidation()
			plan.Steps[0].Action = tc.action
			if tc.action == "ScaleWorkload" {
				replicas := int32(3)
				plan.Steps[0].TargetReplicas = &replicas
			}
			plan.Steps[0].Targets = []ResourceSelector{tc.target}
			if tc.extra != nil {
				plan.Steps[0].Targets = append(plan.Steps[0].Targets, *tc.extra)
			}
			plan.RequiresApproval = true

			if err := plan.Validate(); !errors.Is(err, ErrUnresolvedReference) {
				t.Fatalf("cross-target plan error = %v, want %v", err, ErrUnresolvedReference)
			}
		})
	}

	plan := validResolutionPlanForValidation()
	plan.Target.Kind = "Pod"
	plan.Steps[0].Action = "RestartPod"
	plan.Steps[0].Targets = []ResourceSelector{{Namespace: "default", Kind: "pod", Name: "api"}}
	plan.RequiresApproval = true
	if err := plan.Validate(); err != nil {
		t.Fatalf("canonical Kind match rejected: %v", err)
	}
}

func TestResolutionPlanRequiresBoundedPlanLevelSafetyCriteria(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ResolutionPlan)
		want error
	}{
		{
			name: "missing preconditions",
			edit: func(plan *ResolutionPlan) { plan.Preconditions = nil },
			want: ErrMissingRequired,
		},
		{
			name: "missing postconditions",
			edit: func(plan *ResolutionPlan) { plan.Postconditions = nil },
			want: ErrMissingRequired,
		},
		{
			name: "empty verification criterion",
			edit: func(plan *ResolutionPlan) { plan.Verification = []string{" "} },
			want: ErrMissingRequired,
		},
		{
			name: "oversized precondition",
			edit: func(plan *ResolutionPlan) { plan.Preconditions = []string{strings.Repeat("a", MaxTextBytes+1)} },
			want: ErrTextTooLong,
		},
		{
			name: "excessive postconditions",
			edit: func(plan *ResolutionPlan) { plan.Postconditions = stringsWithEntries(MaxCollectionItems + 1) },
			want: ErrTooManyItems,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := validResolutionPlanForValidation()
			tc.edit(&plan)
			if err := plan.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("resolution validation error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestResolutionCandidateMatchAndStatsValidationBoundsNestedData(t *testing.T) {
	oversized := strings.Repeat("a", MaxTextBytes+1)

	plan := validResolutionPlanForValidation()
	plan.Target.LabelSelector = oversized
	if err := plan.Validate(); !errors.Is(err, ErrTextTooLong) {
		t.Fatalf("resolution nested target error = %v, want %v", err, ErrTextTooLong)
	}

	candidate := validLearningCandidateForValidation()
	candidate.UserFeedback = oversized
	if err := candidate.Validate(); !errors.Is(err, ErrTextTooLong) {
		t.Fatalf("learning feedback error = %v, want %v", err, ErrTextTooLong)
	}

	query := MatchQuery{
		FindingID:       "finding-1",
		FailureCategory: "PodCrashLooping",
		Namespace:       "default",
		Kind:            "Pod",
		Name:            "api",
		Labels:          map[string]string{"app": oversized},
		Selectors:       []ResourceSelector{{Namespace: "default", Kind: "Pod", Name: "api"}},
		MinConfidence:   0.5,
		Limit:           10,
	}
	if err := query.Validate(); !errors.Is(err, ErrTextTooLong) {
		t.Fatalf("match query labels error = %v, want %v", err, ErrTextTooLong)
	}

	query = MatchQuery{MinConfidence: 0.5, Limit: MaxCollectionItems + 1}
	if err := query.Validate(); !errors.Is(err, ErrInvalidCount) {
		t.Fatalf("match query limit error = %v, want %v", err, ErrInvalidCount)
	}

	stats := CatalogStats{Sources: -1}
	if err := stats.Validate(); !errors.Is(err, ErrInvalidCount) {
		t.Fatalf("negative stats error = %v, want %v", err, ErrInvalidCount)
	}

	stats = CatalogStats{Sources: MaxCatalogCount + 1}
	if err := stats.Validate(); !errors.Is(err, ErrInvalidCount) {
		t.Fatalf("excessive stats error = %v, want %v", err, ErrInvalidCount)
	}
}

func TestLearningOutcomeValidationUsesInvalidEnumError(t *testing.T) {
	if err := LearningOutcome("UNKNOWN").Validate(); !errors.Is(err, ErrInvalidLearningOutcome) {
		t.Fatalf("invalid learning outcome error = %v, want %v", err, ErrInvalidLearningOutcome)
	}
}

func validDigestForValidation() PlaybookDigest {
	return PlaybookDigest{
		ID:                "digest-1",
		SourceID:          "source-1",
		Title:             "CrashLoopBackOff restart",
		Summary:           "Restart a crashing pod after evidence review.",
		FailureCategories: []string{"PodCrashLooping"},
		TriggerConditions: []string{"pod restart count increased"},
		Evidence:          []EvidenceRef{{ID: "ev-1", Kind: "Pod", Namespace: "default", Name: "api", Summary: "CrashLoopBackOff"}},
		Steps: []DigestStep{{
			Action:         "Manual",
			Description:    "Review evidence.",
			EvidenceRefs:   []string{"ev-1"},
			Preconditions:  []string{"target UID still matches"},
			Postconditions: []string{"operator verifies state"},
			Confidence:     0.8,
		}},
		Preconditions:  []string{"target UID still matches"},
		Postconditions: []string{"pod becomes Ready"},
		Confidence:     0.8,
	}
}

func validPlaybookForValidation() NormalizedPlaybook {
	return NormalizedPlaybook{
		ID:                "pod-crash",
		Version:           1,
		Lifecycle:         LifecycleNormalized,
		Title:             "Pod crash",
		Summary:           "Restart after validation.",
		FailureCategories: []string{"PodCrashLooping"},
		TriggerConditions: []string{"container waiting"},
		Evidence:          []EvidenceRef{{ID: "ev-1", Kind: "Pod", Namespace: "default", Name: "api", Summary: "CrashLoopBackOff"}},
		Steps: []NormalizedStep{{
			ID:             "step-001",
			Action:         "Manual",
			EvidenceRefs:   []string{"ev-1"},
			Preconditions:  []string{"target UID still matches"},
			Postconditions: []string{"operator verifies state"},
			Confidence:     0.8,
		}},
		Preconditions:  []string{"target UID still matches"},
		Postconditions: []string{"pod becomes Ready"},
		Confidence:     0.8,
	}
}

func validResolutionPlanForValidation() ResolutionPlan {
	playbook := validPlaybookForValidation()
	return ResolutionPlan{
		ID:               "resolution-1",
		FindingID:        "finding-1",
		PlaybookID:       playbook.ID,
		PlaybookVersion:  playbook.Version,
		Target:           ResourceSelector{Namespace: "default", Kind: "Pod", Name: "api"},
		TargetUID:        "uid-1",
		ResourceVersion:  "rv-1",
		Evidence:         playbook.Evidence,
		Rationale:        "restart count increased",
		Steps:            playbook.Steps,
		RequiresApproval: false,
		Confidence:       0.8,
		Preconditions:    []string{"target UID still matches"},
		Postconditions:   []string{"target remains healthy"},
		Verification:     []string{"pod ready"},
	}
}

func validLearningCandidateForValidation() LearningCandidate {
	playbook := validPlaybookForValidation()
	return LearningCandidate{
		ID:             "candidate-1",
		SourceRunID:    "run-1",
		Outcome:        LearningOutcomeVerifiedSuccess,
		Playbook:       playbook,
		BeforeEvidence: playbook.Evidence,
		AfterEvidence:  playbook.Evidence,
		ExecutedSteps:  playbook.Steps,
		IdempotencyKey: "candidate-1",
	}
}

func stringsWithEntries(count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = "value"
	}
	return values
}

func mapWithEntries(count int) map[string]string {
	values := make(map[string]string, count)
	for index := range count {
		values["key-"+string(rune('a'+index%26))+string(rune('A'+index/26))] = "value"
	}
	return values
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
