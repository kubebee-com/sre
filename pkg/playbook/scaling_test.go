package playbook

import (
	"encoding/json"
	"testing"
)

func TestScalingParameterSurvivesNormalization(t *testing.T) {
	digest := validDigestForValidation()
	if err := json.Unmarshal([]byte(`{"id":"scale","action":"ScaleWorkload","target_replicas":3}`), &digest.Steps[0]); err != nil {
		t.Fatal(err)
	}
	normalized, err := NormalizeDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(normalized.Steps[0])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["target_replicas"] != float64(3) {
		t.Fatalf("scaling parameter lost: %s", encoded)
	}
}

func TestScalingParametersValidated(t *testing.T) {
	for _, raw := range []string{
		`{"id":"scale","action":"ScaleWorkload","target_replicas":-1}`,
		`{"id":"scale","action":"ScaleWorkload","target_replicas":10001}`,
		`{"id":"manual","action":"Manual","target_replicas":1}`,
	} {
		var digest DigestStep
		var normalized NormalizedStep
		if err := json.Unmarshal([]byte(raw), &digest); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(raw), &normalized); err != nil {
			t.Fatal(err)
		}
		if err := digest.Validate(); err == nil {
			t.Errorf("digest accepted %s", raw)
		}
		if err := normalized.Validate(); err == nil {
			t.Errorf("normalized accepted %s", raw)
		}
	}
}

func TestScaleExecutionRequiresReplicaCount(t *testing.T) {
	playbook := validGuardedPlaybook()
	playbook.Steps[0].Action = "ScaleWorkload"
	playbook.Steps[0].Targets[0].Kind = "Deployment"
	decision := EvaluateGuardrails(GuardrailPolicy{}, playbook)
	if decision.Allowed || len(decision.Actions) != 0 {
		t.Errorf("missing replicas accepted: %+v", decision)
	}
	plan := validResolutionPlanForValidation()
	plan.Target = playbook.Steps[0].Targets[0]
	plan.Steps = playbook.Steps
	plan.RequiresApproval = true
	if err := plan.Validate(); err == nil {
		t.Fatal("scaling plan accepted missing replicas")
	}
}

func TestScalingParameterCopiesAndAffectsHash(t *testing.T) {
	replicas := int32(3)
	digest := validDigestForValidation()
	digest.Steps[0].Action = "ScaleWorkload"
	digest.Steps[0].TargetReplicas = &replicas
	normalized, err := NormalizeDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	canonical := canonicalNormalizedPlaybook(normalized)
	plan := validResolutionPlanForValidation()
	plan.Steps = normalized.Steps
	canonicalPlan := canonicalResolutionPlan(plan)
	if normalized.Steps[0].TargetReplicas == &replicas {
		t.Error("normalization aliases input replica pointer")
	}
	if canonical.Steps[0].TargetReplicas == normalized.Steps[0].TargetReplicas {
		t.Error("canonical playbook aliases replica pointer")
	}
	if canonicalPlan.Steps[0].TargetReplicas == plan.Steps[0].TargetReplicas {
		t.Error("canonical plan aliases replica pointer")
	}
	planBefore, err := CanonicalHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	before, err := CanonicalHash(normalized)
	if err != nil {
		t.Fatal(err)
	}
	*normalized.Steps[0].TargetReplicas = 4
	after, err := CanonicalHash(normalized)
	if err != nil {
		t.Fatal(err)
	}
	planAfter, err := CanonicalHash(plan)
	if err != nil {
		t.Fatal(err)
	}
	if planBefore == planAfter {
		t.Error("replica change did not change plan hash")
	}
	if before == after {
		t.Error("replica change did not change hash")
	}
	if replicas != 3 || *canonical.Steps[0].TargetReplicas != 3 || *canonicalPlan.Steps[0].TargetReplicas != 3 {
		t.Error("replica mutation leaked into source or canonical copies")
	}
}

func TestScalingBoundsAccepted(t *testing.T) {
	for _, count := range []int32{0, 10000} {
		step := NormalizedStep{ID: "scale", Action: "ScaleWorkload", TargetReplicas: &count}
		if err := step.Validate(); err != nil {
			t.Fatalf("replicas=%d: %v", count, err)
		}
		digest := DigestStep{Action: "ScaleWorkload", TargetReplicas: &count}
		if err := digest.Validate(); err != nil {
			t.Fatalf("digest replicas=%d: %v", count, err)
		}
	}
}
