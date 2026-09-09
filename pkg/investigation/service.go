package investigation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/privacy"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"github.com/kubebee-com/sre/pkg/triage"
	"io"
	"sort"
	"sync"
	"time"
)

var ErrBusy = errors.New("investigation capacity reached; retry later")

type Profile struct {
	Metadata ProviderMetadata
	ID       string
	Version  string
	Runner   triage.StructuredTaskRunner
	Scopes   []identity.Scope
}
type Service struct {
	Guidance         func(context.Context, identity.Principal, identity.Scope) ([]incident.GoldenCase, error)
	ValidateGuidance func(*postgres.Tx, incident.GoldenCase) (bool, error)
	AuthorityEpoch   string
	DB               *postgres.Store
	Policy           *authorization.Policy
	profiles         map[string]Profile
	mu               sync.Mutex
	active           map[string]bool
	slots            chan struct{}
}

func NewService(db *postgres.Store, policy *authorization.Policy, profiles []Profile) (*Service, error) {
	s := &Service{DB: db, Policy: policy, profiles: map[string]Profile{}, active: map[string]bool{}, slots: make(chan struct{}, 2)}
	for _, profile := range profiles {
		if !identity.ValidID(profile.ID) || !identity.ValidID(profile.Version) || len(profile.Scopes) == 0 {
			return nil, postgres.ErrInvalid
		}
		if _, exists := s.profiles[profile.ID]; exists {
			return nil, postgres.ErrConflict
		}
		for _, scope := range profile.Scopes {
			if scope.Validate() != nil {
				return nil, postgres.ErrInvalid
			}
		}
		profile.Scopes = append([]identity.Scope(nil), profile.Scopes...)
		s.profiles[profile.ID] = profile
	}
	return s, nil
}
func (s *Service) Profiles(scope identity.Scope) []string {
	ids := []string{}
	for id, profile := range s.profiles {
		if !profileAllows(profile, scope) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
func (s *Service) Run(ctx context.Context, principal identity.Principal, scope identity.Scope, incidentID, profileID string) (incident.Item, error) {
	if err := s.Policy.Authorize(principal, scope, authorization.Investigate); err != nil {
		return incident.Item{}, err
	}
	if !identity.ValidID(incidentID) || s.DB == nil {
		return incident.Item{}, postgres.ErrInvalid
	}
	profile, ok := s.profiles[profileID]
	if !ok || !profileAllows(profile, scope) {
		return incident.Item{}, postgres.ErrInvalid
	}
	key := scope.Key() + "/" + incidentID
	s.mu.Lock()
	if s.active[key] {
		s.mu.Unlock()
		return incident.Item{}, ErrBusy
	}
	select {
	case s.slots <- struct{}{}:
	default:
		s.mu.Unlock()
		return incident.Item{}, ErrBusy
	}
	s.active[key] = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.active, key); <-s.slots; s.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	now := time.Now().UTC()
	state, err := s.readSnapshot(ctx, scope, incidentID, now)
	if err != nil {
		return incident.Item{}, err
	}
	snapshot, parents, validUntil, environment := state.Evidence, state.Parents, state.ValidUntil, state.Environment
	guidance := []incident.GoldenCase{}
	if s.Guidance != nil {
		cases, err := s.Guidance(ctx, principal, scope)
		if err != nil {
			return incident.Item{}, err
		}
		guidance = applicableGuidance(cases, snapshot, now)
	}
	result := RunResult{RunID: identity.NewID(), ProfileID: profile.ID, ProfileVersion: profile.Version, PrivacyVersion: privacy.Version, PromptVersion: PromptVersion, RubricVersion: RubricVersion, Assessment: Assessment{Status: NeedsEvidence, ReasonCode: "NO_CURRENT_ELIGIBLE_EVIDENCE"}}
	if jobID, ok := ctx.Value(queuedRunKey{}).(string); ok {
		result.RunID = jobID
	}
	if err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if jobID, ok := ctx.Value(queuedRunKey{}).(string); ok {
			job, err := tx.DiagnosticJob(jobID)
			if err != nil {
				return err
			}
			if job.State != "RUNNING" || job.ProfileID != profile.ID || job.IncidentID != incidentID || job.ActorID != principal.ID {
				return postgres.ErrConflict
			}
		}
		return tx.StartRun(result.RunID, incidentID, profile.ID, profile.Version, PromptVersion, RubricVersion, now)
	}); err != nil {
		return incident.Item{}, err
	}
	completed := false
	defer func() {
		if !completed {
			cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.DB.Transact(cleanup, scope, func(tx *postgres.Tx) error {
				return tx.FinishRun(result.RunID, "INTERRUPTED", "RESULT_NOT_COMMITTED", nil)
			})
		}
	}()
	if environment != nil {
		result.EnvironmentVersion = environment.Version
	}
	for _, g := range guidance {
		result.KnowledgeVersions = append(result.KnowledgeVersions, incident.ItemRef{ID: g.ID, Version: g.Version})
	}
	if len(snapshot) > 0 {
		assessment, rounds, next, err := s.assessRounds(ctx, scope, incidentID, profile, state, guidance)
		if err != nil {
			return incident.Item{}, err
		}
		result.Assessment = assessment
		result.Rounds = rounds
		snapshot, parents, validUntil = next.Evidence, next.Parents, next.ValidUntil
	}
	body, _ := json.Marshal(result)
	claim := incident.Item{Scope: scope, IncidentID: incidentID, ID: identity.NewID(), Version: 1, Kind: incident.Claim, Body: body, ObservedAt: time.Now().UTC(), ValidUntil: validUntil, Parents: parents}
	err = s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := s.Policy.Authorize(principal, scope, authorization.Investigate); err != nil {
			return err
		}
		if environment != nil {
			current, err := tx.EnvironmentContext()
			if err != nil {
				return err
			}
			if current.Version != environment.Version {
				return postgres.ErrConflict
			}
		}
		for _, g := range guidance {
			if s.ValidateGuidance == nil {
				return postgres.ErrConflict
			}
			ok, err := s.ValidateGuidance(tx, g)
			if err != nil {
				return err
			}
			if !ok {
				return postgres.ErrConflict
			}
		}
		for _, ref := range parents {
			eligible, err := tx.Eligible(ref, time.Now())
			if err != nil {
				return err
			}
			if !eligible {
				return postgres.ErrConflict
			}
		}
		if !claim.ValidUntil.After(time.Now()) {
			return postgres.ErrConflict
		}
		if jobID, ok := ctx.Value(queuedRunKey{}).(string); ok {
			job, err := tx.DiagnosticJob(jobID)
			if err != nil {
				return err
			}
			if job.State != "RUNNING" {
				return postgres.ErrConflict
			}
		}
		if err := claim.Seal(); err != nil {
			return err
		}
		if err := tx.PutItem(claim); err != nil {
			return err
		}
		if err := tx.FinishRun(result.RunID, string(result.Assessment.Status), result.Assessment.ReasonCode, &incident.ItemRef{ID: claim.ID, Version: claim.Version}); err != nil {
			return err
		}
		if jobID, ok := ctx.Value(queuedRunKey{}).(string); ok {
			if err := tx.FinishDiagnosticJob(jobID, "COMPLETED", &incident.ItemRef{ID: claim.ID, Version: claim.Version}); err != nil {
				return err
			}
		}
		payload, _ := json.Marshal(map[string]string{"incident_id": incidentID, "item_id": claim.ID})
		return tx.Enqueue(result.RunID, "INVESTIGATION_RECORDED", payload)
	})
	if err != nil {
		return incident.Item{}, err
	}
	completed = true
	return claim, nil
}
func strictDecode(raw []byte, value any) error {
	if _, err := incident.CanonicalObject(raw); err != nil {
		return err
	}
	if len(raw) > 65536 {
		return postgres.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return postgres.ErrInvalid
	}
	return nil
}

func profileAllows(profile Profile, scope identity.Scope) bool {
	for _, allowed := range profile.Scopes {
		if allowed == scope {
			return true
		}
	}
	return false
}
