package main

import (
	"bytes"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/evaluation"
	"testing"
)

func TestOfflineCLIAndInvalidBudget(t *testing.T) {
	var out, errout bytes.Buffer
	args := []string{"--dataset", "../../testdata/evaluation/causal-v1.json", "--baseline", "abstain/v1", "--candidate", "conservative/v1"}
	if run(args, &out, &errout) != 0 {
		t.Fatal(errout.String())
	}
	var r evaluation.Report
	if json.Unmarshal(out.Bytes(), &r) != nil || r.CandidateWins == 0 {
		t.Fatal(out.String())
	}
	out.Reset()
	if run(append(args, "--max-calls", "1"), &out, &errout) == 0 || out.Len() != 0 {
		t.Fatal("budget failure emitted success")
	}
	errout.Reset()
	if run([]string{"--dataset", "../../testdata/evaluation/causal-v1.json", "--candidate", "https://live-provider"}, &out, &errout) == 0 || errout.String() != "invalid offline candidate\n" {
		t.Fatal("live provider accepted")
	}
}
