package evaluation

import (
	"context"
	"time"

	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/triage"
)

type Result struct {
	Correct   bool                       `json:"correct"`
	Status    string                     `json:"status"`
	ErrorCode string                     `json:"error_code,omitempty"`
	LatencyMS *float64                   `json:"latency_ms"`
	Usage     *triage.ProviderTokenUsage `json:"usage"`
}
type Pair struct {
	CaseID    string `json:"case_id"`
	Split     string `json:"split"`
	Positive  bool   `json:"positive"`
	Baseline  Result `json:"baseline"`
	Candidate Result `json:"candidate"`
}
type Summary struct {
	RecordingHash   string                     `json:"recording_hash,omitempty"`
	Profile         Profile                    `json:"profile"`
	LatencyOrigin   string                     `json:"latency_origin"`
	Calls           int                        `json:"calls"`
	Correct         int                        `json:"correct"`
	Errors          int                        `json:"errors"`
	PositiveCases   int                        `json:"positive_cases"`
	PositiveCorrect int                        `json:"positive_correct"`
	NegativeCases   int                        `json:"negative_cases"`
	NegativeCorrect int                        `json:"negative_correct"`
	FalsePositives  int                        `json:"false_positives"`
	LatencySamples  int                        `json:"latency_samples"`
	TotalLatencyMS  float64                    `json:"total_latency_ms"`
	UsageSamples    int                        `json:"usage_samples"`
	KnownUsage      triage.ProviderTokenUsage  `json:"known_usage"`
	Usage           *triage.ProviderTokenUsage `json:"usage"`
	CostUSD         *float64                   `json:"cost_usd"`
}
type Report struct {
	Version        string    `json:"version"`
	DatasetVersion string    `json:"dataset_version"`
	DatasetHash    string    `json:"dataset_hash"`
	RubricVersion  string    `json:"rubric_version"`
	StartedAt      time.Time `json:"started_at"`
	CallBudget     int       `json:"call_budget"`
	Baseline       Summary   `json:"baseline"`
	Candidate      Summary   `json:"candidate"`
	CandidateWins  int       `json:"candidate_wins"`
	BaselineWins   int       `json:"baseline_wins"`
	Ties           int       `json:"ties"`
	Pairs          []Pair    `json:"pairs"`
}

func Compare(ctx context.Context, d Dataset, baseline, candidate Runner, budget int) (Report, error) {
	if ctx == nil || baseline == nil || candidate == nil || validateDataset(d) != nil || budget < 2*len(d.Cases) || budget > 512 {
		return Report{}, ErrInvalid
	}
	if baseline.datasetHash() != "" && baseline.datasetHash() != d.Hash || candidate.datasetHash() != "" && candidate.datasetHash() != d.Hash {
		return Report{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Report{}, e
	}
	r := Report{Version: Version, DatasetVersion: d.Version, DatasetHash: d.Hash, RubricVersion: investigation.RubricVersion, StartedAt: time.Now().UTC(), CallBudget: budget, Baseline: Summary{RecordingHash: baseline.artifactHash(), Profile: baseline.profile(), LatencyOrigin: baseline.origin()}, Candidate: Summary{RecordingHash: candidate.artifactHash(), Profile: candidate.profile(), LatencyOrigin: candidate.origin()}}
	for _, c := range d.Cases {
		if e := ctx.Err(); e != nil {
			return Report{}, e
		}
		a := score(baseline.run(ctx, c, d.At), c, d.At)
		b := score(candidate.run(ctx, c, d.At), c, d.At)
		r.Pairs = append(r.Pairs, Pair{CaseID: c.ID, Split: c.Split, Positive: c.ExpectedCause != "", Baseline: a, Candidate: b})
		accumulate(&r.Baseline, a, c)
		accumulate(&r.Candidate, b, c)
		if a.Correct == b.Correct {
			r.Ties++
		} else if b.Correct {
			r.CandidateWins++
		} else {
			r.BaselineWins++
		}
	}
	for _, s := range []*Summary{&r.Baseline, &r.Candidate} {
		if s.UsageSamples == s.Calls {
			u := s.KnownUsage
			s.Usage = &u
		}
	}
	return r, nil
}
func score(o Output, c Case, at time.Time) Result {
	r := Result{LatencyMS: o.LatencyMS, Usage: o.Usage, ErrorCode: o.ErrorCode, Status: "ERROR"}
	if o.ErrorCode != "" || o.Conclusion == nil {
		return r
	}
	assessed, e := investigation.AssessCandidate(*o.Conclusion, c.Evidence, at)
	if e != nil {
		r.ErrorCode = "INVALID_OUTPUT"
		return r
	}
	r.Status = string(assessed.Status)
	if c.ExpectedCause == "" {
		r.Correct = assessed.Status == investigation.NeedsEvidence || assessed.Status == investigation.Inconclusive
	} else {
		r.Correct = assessed.Status == investigation.Hypothesis && o.Conclusion.CauseCode == c.ExpectedCause && o.Conclusion.ResourceHandle == c.ExpectedHandle
	}
	return r
}
func accumulate(s *Summary, r Result, c Case) {
	s.Calls++
	if r.Correct {
		s.Correct++
	}
	if r.Status == "ERROR" {
		s.Errors++
	}
	if c.ExpectedCause != "" {
		s.PositiveCases++
		if r.Correct {
			s.PositiveCorrect++
		}
	} else {
		s.NegativeCases++
		if r.Correct {
			s.NegativeCorrect++
		}
		if r.Status == string(investigation.Hypothesis) {
			s.FalsePositives++
		}
	}
	if r.LatencyMS != nil {
		s.LatencySamples++
		s.TotalLatencyMS += *r.LatencyMS
	}
	if r.Usage != nil {
		s.UsageSamples++
		s.KnownUsage.InputTokens += r.Usage.InputTokens
		s.KnownUsage.OutputTokens += r.Usage.OutputTokens
		s.KnownUsage.TotalTokens += r.Usage.TotalTokens
	}
}
