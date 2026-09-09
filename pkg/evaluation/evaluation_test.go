package evaluation

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/triage"
	"os"
	"testing"
)

func dataset(t *testing.T) Dataset {
	t.Helper()
	b, e := os.ReadFile("../../testdata/evaluation/causal-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	d, e := LoadDataset(b)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestPairedBudgetAndDenominator(t *testing.T) {
	d := dataset(t)
	a, _ := Builtin("abstain/v1")
	b, _ := Builtin("conservative/v1")
	if _, e := Compare(context.Background(), d, a, b, 2*len(d.Cases)-1); e == nil {
		t.Fatal("undersized budget accepted")
	}
	r, e := Compare(context.Background(), d, a, b, 2*len(d.Cases))
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Pairs) != len(d.Cases) || r.Candidate.Calls != len(d.Cases) || r.Candidate.Correct != len(d.Cases) || r.Baseline.Correct >= r.Candidate.Correct {
		t.Fatalf("incorrect paired scoring: %+v", r)
	}
	if r.Candidate.Usage != nil || r.Candidate.CostUSD != nil {
		t.Fatal("invented provider usage or cost")
	}
	if r.CandidateWins == 0 || r.BaselineWins != 0 {
		t.Fatal("paired improvement missing")
	}
}
func TestReplayHashCoverageAndFailureAccounting(t *testing.T) {
	d := dataset(t)
	a, _ := Builtin("conservative/v1")
	replay := Recording{DatasetHash: d.Hash, Profile: Profile{ID: "recorded", Version: "v1", PromptVersion: "test/v1"}, Results: map[string]Output{}}
	for _, c := range d.Cases {
		replay.Results[c.ID] = Output{ErrorCode: "PROVIDER_FAILED"}
	}
	b, _ := json.Marshal(replay)
	p, e := LoadRecording(b, d)
	if e != nil {
		t.Fatal(e)
	}
	r, e := Compare(context.Background(), d, a, p, 2*len(d.Cases))
	if e != nil {
		t.Fatal(e)
	}
	if r.Candidate.Errors != len(d.Cases) || r.Candidate.Correct != 0 || r.BaselineWins != len(d.Cases) {
		t.Fatalf("failed attempts disappeared: %+v", r)
	}
	replay.DatasetHash = "wrong"
	b, _ = json.Marshal(replay)
	if _, e = LoadRecording(b, d); e == nil {
		t.Fatal("wrong dataset accepted")
	}
	replay.DatasetHash = d.Hash
	delete(replay.Results, d.Cases[0].ID)
	b, _ = json.Marshal(replay)
	if _, e = LoadRecording(b, d); e == nil {
		t.Fatal("missing case accepted")
	}
}
func TestDatasetIsFrozenAndStrict(t *testing.T) {
	d := dataset(t)
	if d.Hash != "afcec27c6072bab3edcd70281eb676c27e6df491348c0cbc43755271996df267" {
		t.Fatal("missing hash")
	}
	b, _ := os.ReadFile("../../testdata/evaluation/causal-v1.json")
	if _, e := LoadDataset(append(b, []byte("{}")...)); e == nil {
		t.Fatal("trailing JSON accepted")
	}
	if _, e := Builtin("https://provider.example"); e == nil {
		t.Fatal("arbitrary provider accepted")
	}
}

func TestReplayCannotBeUsedAgainstDifferentSnapshot(t *testing.T) {
	d := dataset(t)
	replay := Recording{DatasetHash: d.Hash, Profile: Profile{ID: "recorded", Version: "v1", PromptVersion: "test/v1"}, Results: map[string]Output{}}
	for _, c := range d.Cases {
		replay.Results[c.ID] = Output{ErrorCode: "TIMEOUT"}
	}
	raw, _ := json.Marshal(replay)
	r, e := LoadRecording(raw, d)
	if e != nil {
		t.Fatal(e)
	}
	d.Cases[0].Evidence[0].Ref.Version++
	raw, _ = json.Marshal(d)
	changed, e := LoadDataset(raw)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := Builtin("abstain/v1")
	if _, e = Compare(context.Background(), changed, a, r, 512); e == nil {
		t.Fatal("recording reused against different evidence snapshot")
	}
}

func TestInvalidReplayIsNotCreditedAsAbstentionAndUsageRemainsPartial(t *testing.T) {
	d := dataset(t)
	a, _ := Builtin("conservative/v1")
	replay := Recording{DatasetHash: d.Hash, Profile: Profile{ID: "recorded", Version: "v2", PromptVersion: "test/v1"}, Results: map[string]Output{}}
	for _, c := range d.Cases {
		replay.Results[c.ID] = a.run(context.Background(), c, d.At)
	}
	first := replay.Results[d.Cases[0].ID]
	first.Usage = &triage.ProviderTokenUsage{InputTokens: 10, OutputTokens: 5, TotalTokens: 15}
	replay.Results[d.Cases[0].ID] = first
	// A fabricated reference is an invalid output, even for an abstention case.
	negative := d.Cases[3]
	broken := replay.Results[negative.ID]
	broken.Conclusion.SupportingEvidence = []incident.ItemRef{{ID: "invented", Version: 1}}
	replay.Results[negative.ID] = broken
	raw, _ := json.Marshal(replay)
	b, e := LoadRecording(raw, d)
	if e != nil {
		t.Fatal(e)
	}
	r, e := Compare(context.Background(), d, a, b, 512)
	if e != nil {
		t.Fatal(e)
	}
	if r.Candidate.Errors != 1 || r.Candidate.Correct != len(d.Cases)-1 || r.Candidate.Usage != nil || r.Candidate.UsageSamples != 1 || r.Candidate.KnownUsage.TotalTokens != 15 || len(r.Candidate.RecordingHash) != 64 {
		t.Fatalf("bad provenance/accounting: %+v", r.Candidate)
	}
	replay.Results[negative.ID] = Output{ErrorCode: "TIMEOUT", Usage: &triage.ProviderTokenUsage{TotalTokens: -1}}
	raw, _ = json.Marshal(replay)
	if _, e = LoadRecording(raw, d); e == nil {
		t.Fatal("negative usage accepted")
	}
	if _, e = LoadDataset([]byte(`{"version":"v1","version":"v2"}`)); e == nil {
		t.Fatal("duplicate keys accepted")
	}
}

func TestReportMutationCannotChangeFrozenReplay(t *testing.T) {
	d := dataset(t)
	a, _ := Builtin("conservative/v1")
	replay := Recording{DatasetHash: d.Hash, Profile: Profile{ID: "recorded", Version: "v1", PromptVersion: "test/v1"}, Results: map[string]Output{}}
	for _, c := range d.Cases {
		o := a.run(context.Background(), c, d.At)
		o.Usage = &triage.ProviderTokenUsage{InputTokens: 1, OutputTokens: 1, TotalTokens: 2}
		replay.Results[c.ID] = o
	}
	raw, _ := json.Marshal(replay)
	b, e := LoadRecording(raw, d)
	if e != nil {
		t.Fatal(e)
	}
	r, e := Compare(context.Background(), d, a, b, 512)
	if e != nil {
		t.Fatal(e)
	}
	r.Pairs[0].Candidate.Usage.TotalTokens = 100
	*r.Pairs[0].Candidate.LatencyMS = 300001
	again, e := Compare(context.Background(), d, a, b, 512)
	if e != nil {
		t.Fatal(e)
	}
	if again.Candidate.Usage.TotalTokens != int64(2*len(d.Cases)) || *again.Pairs[0].Candidate.LatencyMS > 300000 {
		t.Fatal("report mutated private replay")
	}
}
