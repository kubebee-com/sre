package investigation

import (
	"context"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/triage"
	"strings"
	"testing"
	"time"
)

func TestRoundsChallengeTentativeConclusionWithinBudget(t *testing.T) {
	at := time.Now()
	handle := strings.Repeat("a", 32)
	state := snapshotState{Evidence: []EvidenceSnapshot{{Ref: incident.ItemRef{ID: "e", Version: 1}, Observation: privacy.Observation{Code: privacy.ResourcePressure, ResourceHandle: handle, ObservedAt: at, ValidUntil: at.Add(time.Minute)}}}}
	prompts := []string{}
	runner := taskRunnerFunc(func(_ context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
		prompts = append(prompts, task.UserPrompt)
		return triage.StructuredTaskResult{Text: `{"cause_code":"RESOURCE_PRESSURE","resource_handle":"` + handle + `","supporting_evidence":[{"id":"e","version":1}],"contradicting_evidence":[],"alternatives":[]}`}, nil
	})
	s := Service{}
	result, rounds, _, err := s.assessRounds(context.Background(), identity.Scope{}, "incident", Profile{Runner: runner}, state, nil)
	if err != nil || result.Status != Hypothesis || len(rounds) != 3 || len(prompts) != 3 {
		t.Fatal("bounded reasoning failed", err, len(rounds))
	}
	if prompts[0] == prompts[1] || prompts[1] == prompts[2] {
		t.Fatal("repeated identical shallow prompt")
	}
	if !strings.Contains(prompts[1], "CHALLENGE_UPSTREAM") || !strings.Contains(prompts[2], "REASSESS_CURRENT") {
		t.Fatal("missing causal challenge")
	}
	if result.Status == Corroborated {
		t.Fatal("model self corroborated")
	}
}

func TestRefreshStartsIndependentReasoningAndContradictionDoesNotRefresh(t *testing.T) {
	at := time.Now()
	handle := strings.Repeat("a", 32)
	old := snapshotState{Evidence: []EvidenceSnapshot{{Ref: incident.ItemRef{ID: "e", Version: 1}, Observation: privacy.Observation{Code: privacy.ResourcePressure, ResourceHandle: handle, ObservedAt: at, ValidUntil: at.Add(time.Minute)}}}, Parents: []incident.ItemRef{{ID: "e", Version: 1}}}
	fresh := old
	fresh.Evidence = append([]EvidenceSnapshot(nil), old.Evidence...)
	fresh.Evidence[0].Ref.Version = 2
	fresh.Parents = []incident.ItemRef{{ID: "e", Version: 2}}
	calls := 0
	runner := taskRunnerFunc(func(_ context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
		calls++
		if calls == 2 && strings.Contains(task.UserPrompt, "tentative_this_run_only") {
			t.Fatal("old tentative cause survived evidence replacement")
		}
		version := "2"
		checks := ""
		if calls == 1 {
			version = "1"
			checks = `,"requested_checks":[{"kind":"REFRESH_RESOURCE_STATE","resource_handle":"` + handle + `"}]`
		}
		return triage.StructuredTaskResult{Text: `{"cause_code":"RESOURCE_PRESSURE","resource_handle":"` + handle + `","supporting_evidence":[{"id":"e","version":` + version + `}],"contradicting_evidence":[],"alternatives":[]` + checks + `}`}, nil
	})
	s := Service{}
	assessment, _, result, err := s.assessRoundsWithRefresh(context.Background(), identity.Scope{}, "i", Profile{Runner: runner}, old, nil, func([]Check, snapshotState) (snapshotState, bool, error) { return fresh, true, nil })
	if err != nil || assessment.Status != Hypothesis || len(result.Parents) != 1 || result.Parents[0].Version != 2 {
		t.Fatal("independent refreshed conclusion failed", err)
	}
	healthy := old.Evidence[0]
	healthy.Ref.ID = "healthy"
	healthy.Observation.Code = privacy.Healthy
	old.Evidence = append(old.Evidence, healthy)
	calls = 0
	assessment, _, result, err = s.assessRoundsWithRefresh(context.Background(), identity.Scope{}, "i", Profile{Runner: runner}, old, nil, func([]Check, snapshotState) (snapshotState, bool, error) {
		t.Fatal("contradiction replaced its cited evidence")
		return fresh, true, nil
	})
	if err != nil || assessment.Status != Inconclusive || result.Parents[0].Version != 1 {
		t.Fatal("inconclusive provenance changed", err)
	}
}
