package evaluation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/triage"
)

type Profile struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	PromptVersion string `json:"prompt_version"`
}
type Output struct {
	Conclusion *investigation.Conclusion  `json:"conclusion,omitempty"`
	ErrorCode  string                     `json:"error_code,omitempty"`
	LatencyMS  *float64                   `json:"latency_ms"`
	Usage      *triage.ProviderTokenUsage `json:"usage"`
}
type Recording struct {
	DatasetHash string            `json:"dataset_hash"`
	Profile     Profile           `json:"profile"`
	Results     map[string]Output `json:"results"`
}

// Runner is deliberately closed to the offline implementations in this package.
// Live provider calls require a separate authorized collection workflow.
type Runner interface {
	profile() Profile
	origin() string
	datasetHash() string
	artifactHash() string
	run(context.Context, Case, time.Time) Output
}
type builtin struct{ name string }

func Builtin(name string) (Runner, error) {
	if name != "conservative/v1" && name != "abstain/v1" {
		return nil, ErrInvalid
	}
	return builtin{name}, nil
}
func (b builtin) profile() Profile {
	return Profile{ID: b.name, Version: "v1", PromptVersion: "deterministic/v1"}
}
func (b builtin) datasetHash() string  { return "" }
func (b builtin) artifactHash() string { return "" }
func (b builtin) origin() string       { return "MEASURED_OFFLINE" }
func (b builtin) run(ctx context.Context, c Case, at time.Time) Output {
	start := time.Now()
	handle := "00000000000000000000000000000000"
	if len(c.Evidence) > 0 {
		handle = c.Evidence[0].Observation.ResourceHandle
	}
	conclusion := investigation.Conclusion{CauseCode: privacy.Unclassified, ResourceHandle: handle}
	if b.name == "conservative/v1" {
		obs := make([]privacy.Observation, 0, len(c.Evidence))
		for _, e := range c.Evidence {
			obs = append(obs, e.Observation)
		}
		for _, e := range c.Evidence {
			o := e.Observation
			if o.ObservedAt.After(at) || !o.ValidUntil.After(at) {
				continue
			}
			// Restrict the shared guidance predicate to this exact resource so another
			// resource's uncontradicted observation cannot authorize this candidate.
			same := []privacy.Observation{}
			for _, o2 := range obs {
				if o2.ResourceHandle == o.ResourceHandle {
					same = append(same, o2)
				}
			}
			if privacy.SuggestCause(string(o.Code), same, at) {
				conclusion = investigation.Conclusion{CauseCode: o.Code, ResourceHandle: o.ResourceHandle, SupportingEvidence: []incident.ItemRef{e.Ref}}
				break
			}
		}
	}
	latency := float64(time.Since(start).Nanoseconds()) / 1e6
	return Output{Conclusion: &conclusion, LatencyMS: &latency}
}

type recorded struct {
	record Recording
	hash   string
}

func (r recorded) datasetHash() string  { return r.record.DatasetHash }
func (r recorded) artifactHash() string { return r.hash }
func (r recorded) profile() Profile     { return r.record.Profile }
func (r recorded) origin() string       { return "RECORDED_UNVERIFIED" }
func (r recorded) run(_ context.Context, c Case, _ time.Time) Output {
	o := r.record.Results[c.ID]
	if o.Usage != nil {
		u := *o.Usage
		o.Usage = &u
	}
	if o.LatencyMS != nil {
		latency := *o.LatencyMS
		o.LatencyMS = &latency
	}
	return o
}
func LoadRecording(raw []byte, d Dataset) (Runner, error) {
	var r Recording
	if strict(raw, &r) != nil || r.DatasetHash != d.Hash || !validVersion(r.Profile.ID) || !validVersion(r.Profile.Version) || !validVersion(r.Profile.PromptVersion) || len(r.Results) != len(d.Cases) {
		return nil, ErrInvalid
	}
	for _, c := range d.Cases {
		o, ok := r.Results[c.ID]
		if !ok || (o.Conclusion == nil) == (o.ErrorCode == "") {
			return nil, ErrInvalid
		}
		if o.ErrorCode != "" && o.ErrorCode != "PROVIDER_FAILED" && o.ErrorCode != "TIMEOUT" && o.ErrorCode != "INVALID_OUTPUT" && o.ErrorCode != "BUDGET_EXCEEDED" {
			return nil, ErrInvalid
		}
		if o.LatencyMS != nil && (*o.LatencyMS < 0 || *o.LatencyMS > 300000) {
			return nil, ErrInvalid
		}
		if o.Usage != nil {
			u := o.Usage
			if u.InputTokens < 0 || u.OutputTokens < 0 || u.TotalTokens < 0 || u.InputTokens > 1000000 || u.OutputTokens > 1000000 || u.TotalTokens > 2000000 || u.TotalTokens != u.InputTokens+u.OutputTokens {
				return nil, ErrInvalid
			}
		}
	}
	// Decode into a private copy; later caller mutation cannot change a replay.
	canonical, _ := json.Marshal(r)
	sum := sha256.Sum256(canonical)
	return recorded{record: r, hash: hex.EncodeToString(sum[:])}, nil
}
func validateDataset(d Dataset) error {
	raw, e := json.Marshal(d)
	if e != nil {
		return ErrInvalid
	}
	fresh, e := LoadDataset(raw)
	if e != nil || fresh.Hash != d.Hash {
		return ErrInvalid
	}
	return nil
}
