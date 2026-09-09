package collection

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/investigation"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/triage"
	"time"
)

type ProviderResolver func(investigation.ProviderMetadata) (triage.StructuredTaskRunner, error)

// RunDiagnostics participates in the same enrolled collector session as Run.
// It never reads stdin and never uses execution credentials. A lost connection or
// revoked lease cancels inference; only the orchestrator can accept the result.
func (r *Runtime) RunDiagnostics(ctx context.Context, profiles []string, resolve ProviderResolver) error {
	if len(profiles) == 0 || len(profiles) > 32 {
		return ErrRuntime
	}
	if resolve == nil {
		resolve = investigation.ResolveLocalProvider
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		token, ready := r.diagnosticToken()
		if !ready {
			continue
		}
		var claim *investigation.AgentClaim
		err := r.client.post(ctx, "/agent/diagnostics/claim", token, struct {
			Profiles []string `json:"profiles"`
		}{profiles}, &claim)
		if errors.Is(err, ErrReenrollment) {
			return err
		}
		if err != nil || claim == nil {
			continue
		}
		if claim.Input.Scope != r.config.Scope || !claim.LeaseUntil.After(time.Now()) {
			return ErrRuntime
		}
		allowed := false
		for _, id := range profiles {
			if id == claim.Input.ProfileID {
				allowed = true
			}
		}
		if !allowed {
			return ErrRuntime
		}
		if err = r.runDiagnostic(ctx, *claim, resolve); errors.Is(err, ErrReenrollment) {
			return err
		}
	}
}
func (r *Runtime) diagnosticToken() (string, bool) {
	session := r.diagnosticSession.Load()
	if session == nil {
		return "", false
	}
	return session.Token, r.validCredential(*session)
}
func (r *Runtime) runDiagnostic(parent context.Context, claim investigation.AgentClaim, resolve ProviderResolver) error {
	r.diagnosticActive.Store(true)
	defer r.diagnosticActive.Store(false)
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	done := make(chan struct{})
	defer func() { cancel(); <-done }()
	path := "/agent/diagnostics/" + claim.Input.JobID
	go func() {
		defer close(done)
		ticker := time.NewTicker(8 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			token, ok := r.diagnosticToken()
			if !ok {
				cancel()
				return
			}
			var out struct {
				LeaseUntil time.Time `json:"lease_until"`
			}
			if r.client.post(ctx, path+"/heartbeat", token, struct {
				AttemptID string `json:"attempt_id"`
			}{claim.AttemptID}, &out) != nil || !out.LeaseUntil.After(time.Now()) {
				cancel()
				return
			}
		}
	}()
	result := investigation.RunResult{RunID: claim.Input.JobID, ProfileID: claim.Input.ProfileID, ProfileVersion: claim.Input.ProfileVersion, PrivacyVersion: privacy.Version, PromptVersion: investigation.PromptVersion, RubricVersion: investigation.RubricVersion, Assessment: investigation.Assessment{Status: investigation.NeedsEvidence, ReasonCode: "NO_CURRENT_ELIGIBLE_EVIDENCE"}}
	runner, err := resolve(claim.Input.Provider)
	if err != nil {
		result.Assessment = investigation.Assessment{Status: investigation.Inconclusive, ReasonCode: "PROVIDER_UNAVAILABLE"}
	} else if len(claim.Input.Snapshot.Evidence) > 0 {
		result.Assessment, result.Rounds, _, err = investigation.ExecuteRounds(ctx, runner, claim.Input.Snapshot, claim.Input.Guidance, func(checks []investigation.Check, current investigation.Snapshot) (investigation.Snapshot, bool, error) {
			token, ok := r.diagnosticToken()
			if !ok {
				return current, false, ErrReenrollment
			}
			var next *investigation.Snapshot
			err := r.client.post(ctx, path+"/refresh", token, struct {
				AttemptID string                `json:"attempt_id"`
				Checks    []investigation.Check `json:"checks"`
			}{claim.AttemptID, checks}, &next)
			if err != nil {
				return current, false, err
			}
			if next == nil {
				return current, false, nil
			}
			return *next, true, nil
		})
		if err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	token, ok := r.diagnosticToken()
	if !ok {
		return ErrReenrollment
	}
	return r.client.post(ctx, path+"/complete", token, struct {
		AttemptID string                  `json:"attempt_id"`
		Result    investigation.RunResult `json:"result"`
	}{claim.AttemptID, result}, nil)
}
