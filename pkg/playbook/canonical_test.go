package playbook

import "testing"

func TestCanonicalHashIsStableAcrossInputOrdering(t *testing.T) {
	first := NormalizedPlaybook{
		ID:        "pod-crash",
		Version:   1,
		Lifecycle: LifecycleNormalized,
		Title:     "Pod crash",
		Summary:   "Restart after validation.",
		FailureCategories: []string{
			"PodCrashLooping",
			"PodNotReady",
		},
		TriggerConditions: []string{
			"restart count increased",
			"container waiting",
		},
		Evidence: []EvidenceRef{
			{ID: "b", Kind: "Event", Namespace: "default", Name: "api", Summary: "BackOff"},
			{ID: "a", Kind: "Pod", Namespace: "default", Name: "api", Summary: "CrashLoopBackOff"},
		},
		Steps: []NormalizedStep{
			{ID: "b", Action: "Manual", Description: "inspect", EvidenceRefs: []string{"b", "a"}},
			{ID: "a", Action: "RestartPod", Description: "restart", EvidenceRefs: []string{"a"}},
		},
		Preconditions:  []string{"uid matches"},
		Postconditions: []string{"pod ready"},
		Confidence:     0.95,
	}
	second := first
	second.FailureCategories = []string{"PodNotReady", "PodCrashLooping"}
	second.TriggerConditions = []string{"container waiting", "restart count increased"}
	second.Evidence = []EvidenceRef{
		{ID: "a", Kind: "Pod", Namespace: "default", Name: "api", Summary: "CrashLoopBackOff"},
		{ID: "b", Kind: "Event", Namespace: "default", Name: "api", Summary: "BackOff"},
	}
	second.Steps = []NormalizedStep{
		{ID: "a", Action: "RestartPod", Description: "restart", EvidenceRefs: []string{"a"}},
		{ID: "b", Action: "Manual", Description: "inspect", EvidenceRefs: []string{"a", "b"}},
	}

	left, err := CanonicalHash(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("hashes differ: %q != %q", left, right)
	}
	if len(left) != 64 {
		t.Fatalf("hash length = %d, want 64", len(left))
	}
}

func TestCanonicalHashDoesNotMutateInput(t *testing.T) {
	playbook := NormalizedPlaybook{
		ID:                "pod-crash",
		Version:           1,
		Lifecycle:         LifecycleNormalized,
		Title:             "Pod crash",
		Summary:           "Restart after validation.",
		FailureCategories: []string{"z", "a"},
		TriggerConditions: []string{"z", "a"},
		Evidence:          []EvidenceRef{{ID: "z"}, {ID: "a"}},
		Steps: []NormalizedStep{
			{ID: "z", EvidenceRefs: []string{"z", "a"}},
			{ID: "a", EvidenceRefs: []string{"a"}},
		},
		Preconditions:  []string{"uid matches"},
		Postconditions: []string{"pod ready"},
		Confidence:     0.9,
	}

	if _, err := CanonicalHash(playbook); err != nil {
		t.Fatal(err)
	}
	if playbook.FailureCategories[0] != "z" || playbook.Steps[0].ID != "z" || playbook.Steps[0].EvidenceRefs[0] != "z" {
		t.Fatalf("CanonicalHash mutated input: %#v", playbook)
	}
}

func TestCanonicalHashIgnoresOperationalMetadata(t *testing.T) {
	first := validPlaybookForValidation()
	first.Version = 1
	first.Lifecycle = LifecycleNormalized
	first.CanonicalHash = "old-hash"
	first.CreatedAt = mustParseTime(t, "2026-09-07T01:02:03Z")

	second := first
	second.Version = 99
	second.Lifecycle = LifecycleActive
	second.CanonicalHash = "new-hash"
	second.CreatedAt = mustParseTime(t, "2026-09-08T04:05:06Z")

	left, err := CanonicalHash(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("operational metadata changed content hash: %q != %q", left, right)
	}
}

func TestCanonicalHashIgnoresKubernetesEvidenceIdentity(t *testing.T) {
	first := validPlaybookForValidation()
	first.Evidence[0].UID = "uid-old"
	first.Evidence[0].ResourceVersion = "rv-old"

	second := first
	second.Evidence = append([]EvidenceRef(nil), first.Evidence...)
	second.Evidence[0].UID = "uid-new"
	second.Evidence[0].ResourceVersion = "rv-new"

	left, err := CanonicalHash(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("Kubernetes evidence identity changed content hash: %q != %q", left, right)
	}
	if first.Evidence[0].UID != "uid-old" || first.Evidence[0].ResourceVersion != "rv-old" {
		t.Fatalf("CanonicalHash mutated evidence identity: %#v", first.Evidence[0])
	}
}

func TestCanonicalHashCopiesAndSortsResolutionPlanSafetyCriteria(t *testing.T) {
	first := validResolutionPlanForValidation()
	first.Preconditions = []string{"z condition", "a condition"}
	first.Postconditions = []string{"z result", "a result"}
	first.Verification = []string{"z check", "a check"}
	first.Uncertainties = []string{"z uncertainty", "a uncertainty"}
	first.Evidence = []EvidenceRef{{ID: "ev-2"}, {ID: "ev-1"}}
	first.Steps[0].EvidenceRefs = []string{"ev-2", "ev-1"}

	second := first
	second.Preconditions = []string{"a condition", "z condition"}
	second.Postconditions = []string{"a result", "z result"}
	second.Verification = []string{"a check", "z check"}
	second.Uncertainties = []string{"a uncertainty", "z uncertainty"}
	second.Evidence = []EvidenceRef{{ID: "ev-1"}, {ID: "ev-2"}}
	second.Steps = append([]NormalizedStep(nil), first.Steps...)
	second.Steps[0].EvidenceRefs = []string{"ev-1", "ev-2"}

	left, err := CanonicalHash(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("resolution plan hashes differ: %q != %q", left, right)
	}
	if first.Preconditions[0] != "z condition" || first.Evidence[0].ID != "ev-2" || first.Steps[0].EvidenceRefs[0] != "ev-2" {
		t.Fatalf("CanonicalHash mutated resolution plan: %#v", first)
	}
}

func TestCanonicalHashIgnoresResolutionTargetIdentity(t *testing.T) {
	first := validResolutionPlanForValidation()
	first.TargetUID = "uid-old"
	first.ResourceVersion = "rv-old"
	first.Evidence[0].UID = "evidence-uid-old"
	first.Evidence[0].ResourceVersion = "evidence-rv-old"

	second := first
	second.TargetUID = "uid-new"
	second.ResourceVersion = "rv-new"
	second.Evidence = append([]EvidenceRef(nil), first.Evidence...)
	second.Evidence[0].UID = "evidence-uid-new"
	second.Evidence[0].ResourceVersion = "evidence-rv-new"

	left, err := CanonicalHash(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := CanonicalHash(second)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("resolution target identity changed content hash: %q != %q", left, right)
	}
	if first.TargetUID != "uid-old" || first.ResourceVersion != "rv-old" || first.Evidence[0].UID != "evidence-uid-old" {
		t.Fatalf("CanonicalHash mutated resolution identity: %#v", first)
	}
}
