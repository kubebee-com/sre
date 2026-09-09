package playbook

import "testing"

func TestNormalizeDigestAssignsDeterministicIDsOrderDefaultsAndHash(t *testing.T) {
	digest := PlaybookDigest{
		ID:       "Digest-1",
		SourceID: "Source-1",
		Title:    "Pod Crash",
		Summary:  "Restart a pod after bounded checks.",
		FailureCategories: []string{
			"PodNotReady",
			"PodCrashLooping",
		},
		TriggerConditions: []string{
			"restart count increased",
			"container waiting",
		},
		Evidence: []EvidenceRef{{ID: "ev-1", Kind: "pod", Namespace: "default", Name: "api", Summary: "CrashLoopBackOff"}},
		Steps: []DigestStep{
			{Action: "Manual", Description: "inspect", EvidenceRefs: []string{"ev-1"}, Preconditions: []string{"uid matches"}, Postconditions: []string{"operator reviewed"}, Confidence: 0.9},
			{Action: "RestartPod", Description: "restart", EvidenceRefs: []string{"ev-1"}, Targets: []ResourceSelector{{Namespace: "default", Kind: "pod", Name: "api"}}, Preconditions: []string{"uid matches"}, Postconditions: []string{"pod ready"}, Confidence: 0.95},
		},
		Preconditions:  []string{"uid matches"},
		Postconditions: []string{"pod ready"},
		Confidence:     0.9,
	}

	first, err := NormalizeDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NormalizeDigest(digest)
	if err != nil {
		t.Fatal(err)
	}

	if first.ID != "digest-1" || first.Version != 1 || first.Lifecycle != LifecycleNormalized {
		t.Fatalf("unexpected normalized identity/defaults: %#v", first)
	}
	if len(first.Steps) != 2 || first.Steps[0].ID != "step-001" || first.Steps[1].ID != "step-002" {
		t.Fatalf("unexpected deterministic step IDs/order: %#v", first.Steps)
	}
	if first.Steps[1].Targets[0].Namespace != "default" || first.Steps[1].Targets[0].Kind != "Pod" {
		t.Fatalf("selector was not canonicalized: %#v", first.Steps[1].Targets[0])
	}
	if first.CanonicalHash == "" || first.CanonicalHash != second.CanonicalHash {
		t.Fatalf("canonical hash is not deterministic: %q vs %q", first.CanonicalHash, second.CanonicalHash)
	}
}

func TestNormalizeDigestPreservesUnknownActionForGuardrails(t *testing.T) {
	digest := PlaybookDigest{
		ID:                "unsafe",
		SourceID:          "source",
		Title:             "Unsafe",
		Summary:           "Imported shell content.",
		FailureCategories: []string{"PodCrashLooping"},
		TriggerConditions: []string{"event observed"},
		Evidence:          []EvidenceRef{{ID: "ev-1", Kind: "Pod", Namespace: "default", Name: "api", Summary: "BackOff"}},
		Steps: []DigestStep{{
			Action:         "kubectl exec",
			Command:        "kubectl exec api -- rm -rf /",
			Description:    "do not coerce",
			EvidenceRefs:   []string{"ev-1"},
			Preconditions:  []string{"uid matches"},
			Postconditions: []string{"manual review"},
			Confidence:     0.9,
		}},
		Preconditions:  []string{"uid matches"},
		Postconditions: []string{"manual review"},
		Confidence:     0.9,
	}

	normalized, err := NormalizeDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Steps[0].Action != "kubectl exec" {
		t.Fatalf("unknown action was coerced to %q", normalized.Steps[0].Action)
	}
}
