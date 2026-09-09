package remediation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
)

const (
	proposalStoreSchema  = "kubebee.sre/proposals"
	proposalStoreVersion = 1
	proposalStateFile    = "proposals.json"
)

var (
	ErrProposalNotFound  = errors.New("proposal not found")
	ErrProposalExists    = errors.New("proposal already exists")
	ErrInvalidTransition = errors.New("invalid proposal transition")
	ErrStoreClosed       = errors.New("proposal store is closed")
	ErrActorRequired     = errors.New("authenticated actor is required")
	ErrProposalExpired   = errors.New("proposal has expired")
)

var auditIDSequence atomic.Uint64

type ProposalStatus string

const (
	StatusPending   ProposalStatus = "PENDING_APPROVAL"
	StatusApproved  ProposalStatus = "APPROVED"
	StatusRejected  ProposalStatus = "REJECTED"
	StatusExecuting ProposalStatus = "EXECUTING"
	StatusCompleted ProposalStatus = "COMPLETED"
	StatusFailed    ProposalStatus = "FAILED"
	StatusStale     ProposalStatus = "STALE"
	StatusExpired   ProposalStatus = "EXPIRED"
)

type AuditEventType string

const (
	AuditEventCreate    AuditEventType = "create"
	AuditEventApprove   AuditEventType = "approve"
	AuditEventReject    AuditEventType = "reject"
	AuditEventExecution AuditEventType = "execution"
	AuditEventStale     AuditEventType = "stale"
	AuditEventFailure   AuditEventType = "failure"
	AuditEventCleanup   AuditEventType = "cleanup"
	AuditEventExpire    AuditEventType = "expire"
)

type AuditEvent struct {
	ID         string         `json:"id"`
	ProposalID string         `json:"proposal_id"`
	Type       AuditEventType `json:"type"`
	Actor      string         `json:"actor,omitempty"`
	FromStatus ProposalStatus `json:"from_status,omitempty"`
	ToStatus   ProposalStatus `json:"to_status,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Message    string         `json:"message,omitempty"`
	At         time.Time      `json:"at"`
}

// ProposalStore is the atomic persistence boundary for remediation state.
// Implementations must return independent copies from every read operation.
type ProposalStore interface {
	Create(*Proposal) error
	Get(string) (*Proposal, error)
	List() ([]*Proposal, error)
	Transition(string, ProposalStatus, ProposalStatus, func(*Proposal) error, AuditEvent) (*Proposal, error)
	AuditEvents(string) ([]AuditEvent, error)
	ListAuditEvents(string) ([]AuditEvent, error)
	Close() error
}

type proposalState struct {
	Schema    string       `json:"schema"`
	Version   int          `json:"version"`
	Proposals []*Proposal  `json:"proposals"`
	Audit     []AuditEvent `json:"audit"`
}

func newProposalState() proposalState {
	return proposalState{
		Schema:    proposalStoreSchema,
		Version:   proposalStoreVersion,
		Proposals: make([]*Proposal, 0),
		Audit:     make([]AuditEvent, 0),
	}
}

func validateProposalState(state proposalState) error {
	if state.Schema != proposalStoreSchema {
		return fmt.Errorf("unsupported proposal store schema %q", state.Schema)
	}
	if state.Version != proposalStoreVersion {
		return fmt.Errorf("unsupported proposal store version %d", state.Version)
	}
	if state.Proposals == nil {
		state.Proposals = make([]*Proposal, 0)
	}
	if state.Audit == nil {
		state.Audit = make([]AuditEvent, 0)
	}
	return nil
}

type memoryProposalStore struct {
	mu     sync.RWMutex
	state  proposalState
	closed bool
}

func NewMemoryProposalStore() ProposalStore {
	return &memoryProposalStore{state: newProposalState()}
}

func (s *memoryProposalStore) Create(proposal *Proposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := validateProposalForStore(proposal); err != nil {
		return err
	}
	for _, existing := range s.state.Proposals {
		if existing.ID == proposal.ID {
			return ErrProposalExists
		}
	}
	copy := sanitizeProposalForStore(proposal)
	s.state.Proposals = append(s.state.Proposals, copy)
	s.state.Audit = append(s.state.Audit, newCreateAudit(copy))
	return nil
}

func (s *memoryProposalStore) Get(id string) (*Proposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	for _, proposal := range s.state.Proposals {
		if proposal.ID == id {
			return cloneProposal(proposal), nil
		}
	}
	return nil, ErrProposalNotFound
}

func (s *memoryProposalStore) List() ([]*Proposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	return cloneAndSortProposals(s.state.Proposals), nil
}

func (s *memoryProposalStore) Transition(id string, from, to ProposalStatus, mutate func(*Proposal) error, event AuditEvent) (*Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	return transitionState(&s.state, id, from, to, mutate, event)
}

func (s *memoryProposalStore) AuditEvents(proposalID string) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	return cloneAuditEvents(filterAuditEvents(s.state.Audit, proposalID)), nil
}

func (s *memoryProposalStore) ListAuditEvents(proposalID string) ([]AuditEvent, error) {
	return s.AuditEvents(proposalID)
}

func (s *memoryProposalStore) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return nil
}

// FileProposalStore persists one versioned state document. Each mutation is
// written to a 0600 temporary file, synced, renamed, and followed by a
// directory sync so a process restart cannot observe a partially-written file.
type FileProposalStore struct {
	lockFile *os.File
	mu       sync.RWMutex
	dir      string
	path     string
	state    proposalState
	closed   bool
}

func NewFileProposalStore(dir string) (*FileProposalStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("proposal store directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create proposal store directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("restrict proposal store directory: %w", err)
	}

	lockFile, err := lockProposalDirectory(dir)
	if err != nil {
		return nil, err
	}
	opened := false
	defer func() {
		if !opened {
			_ = lockFile.Close()
		}
	}()
	store := &FileProposalStore{dir: dir, path: filepath.Join(dir, proposalStateFile), state: newProposalState(), lockFile: lockFile}
	encoded, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		opened = true
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read proposal store: %w", err)
	}
	if err := os.Chmod(store.path, 0o600); err != nil {
		return nil, fmt.Errorf("restrict proposal store: %w", err)
	}
	if err := json.Unmarshal(encoded, &store.state); err != nil {
		return nil, fmt.Errorf("decode proposal store: %w", err)
	}
	if err := validateProposalState(store.state); err != nil {
		return nil, err
	}
	for _, proposal := range store.state.Proposals {
		if err := validateProposalForStore(proposal); err != nil {
			return nil, fmt.Errorf("validate proposal %q: %w", proposal.ID, err)
		}
	}
	seenIDs := make(map[string]struct{}, len(store.state.Proposals))
	for _, proposal := range store.state.Proposals {
		if _, exists := seenIDs[proposal.ID]; exists {
			return nil, fmt.Errorf("duplicate proposal ID %q", proposal.ID)
		}
		seenIDs[proposal.ID] = struct{}{}
	}
	opened = true
	return store, nil
}

func (s *FileProposalStore) Create(proposal *Proposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if err := validateProposalForStore(proposal); err != nil {
		return err
	}
	for _, existing := range s.state.Proposals {
		if existing.ID == proposal.ID {
			return ErrProposalExists
		}
	}
	state := cloneState(s.state)
	copy := sanitizeProposalForStore(proposal)
	state.Proposals = append(state.Proposals, copy)
	state.Audit = append(state.Audit, newCreateAudit(copy))
	if err := s.writeStateLocked(state); err != nil {
		return err
	}
	s.state = state
	return nil
}

func (s *FileProposalStore) Get(id string) (*Proposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	for _, proposal := range s.state.Proposals {
		if proposal.ID == id {
			return cloneProposal(proposal), nil
		}
	}
	return nil, ErrProposalNotFound
}

func (s *FileProposalStore) List() ([]*Proposal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	return cloneAndSortProposals(s.state.Proposals), nil
}

func (s *FileProposalStore) Transition(id string, from, to ProposalStatus, mutate func(*Proposal) error, event AuditEvent) (*Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	state := cloneState(s.state)
	proposal, err := transitionState(&state, id, from, to, mutate, event)
	if err != nil {
		return nil, err
	}
	if err := s.writeStateLocked(state); err != nil {
		return nil, err
	}
	s.state = state
	return cloneProposal(proposal), nil
}

func (s *FileProposalStore) AuditEvents(proposalID string) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	return cloneAuditEvents(filterAuditEvents(s.state.Audit, proposalID)), nil
}

func (s *FileProposalStore) ListAuditEvents(proposalID string) ([]AuditEvent, error) {
	return s.AuditEvents(proposalID)
}

func (s *FileProposalStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lockFile != nil {
		return s.lockFile.Close()
	}
	return nil
}

func (s *FileProposalStore) writeStateLocked(state proposalState) error {
	if err := validateProposalState(state); err != nil {
		return err
	}
	state = sanitizeStateForStore(state)
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode proposal store: %w", err)
	}
	temp, err := os.CreateTemp(s.dir, ".proposals-*.tmp")
	if err != nil {
		return fmt.Errorf("create proposal store temporary file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("restrict proposal store temporary file: %w", err)
	}
	if _, err := temp.Write(encoded); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write proposal store: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync proposal store: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close proposal store temporary file: %w", err)
	}
	if err := os.Rename(tempName, s.path); err != nil {
		return fmt.Errorf("replace proposal store: %w", err)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("restrict proposal store: %w", err)
	}
	directory, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("open proposal store directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync proposal store directory: %w", err)
	}
	return nil
}

func transitionState(state *proposalState, id string, from, to ProposalStatus, mutate func(*Proposal) error, event AuditEvent) (*Proposal, error) {
	for index, proposal := range state.Proposals {
		if proposal.ID != id {
			continue
		}
		if proposal.Status != from || !validProposalTransition(from, to) {
			return nil, fmt.Errorf("%w: %s to %s", ErrInvalidTransition, proposal.Status, to)
		}
		updated := cloneProposal(proposal)
		if mutate != nil {
			if err := mutate(updated); err != nil {
				return nil, err
			}
		}
		updated.Status = to
		updated.Revision++
		updated.UpdatedAt = time.Now().UTC()
		state.Proposals[index] = sanitizeProposalForStore(updated)
		event = normalizeAuditEvent(event, updated, from, to)
		state.Audit = append(state.Audit, event)
		return cloneProposal(state.Proposals[index]), nil
	}
	return nil, ErrProposalNotFound
}

func validProposalTransition(from, to ProposalStatus) bool {
	switch from {
	case StatusPending:
		return to == StatusApproved || to == StatusRejected || to == StatusStale || to == StatusExpired
	case StatusApproved:
		return to == StatusExecuting || to == StatusStale || to == StatusExpired
	case StatusExecuting:
		return to == StatusCompleted || to == StatusFailed || to == StatusStale
	default:
		return false
	}
}

func validateProposalForStore(proposal *Proposal) error {
	if proposal == nil {
		return errors.New("proposal is required")
	}
	if strings.TrimSpace(proposal.ID) == "" {
		return errors.New("proposal ID is required")
	}
	if !validProposalStatus(proposal.Status) && proposal.Status != "" {
		return fmt.Errorf("unsupported proposal status %q", proposal.Status)
	}
	if proposal.Status == "" {
		proposal.Status = StatusPending
	}
	if proposal.CreatedAt.IsZero() {
		proposal.CreatedAt = time.Now().UTC()
	}
	if proposal.UpdatedAt.IsZero() {
		proposal.UpdatedAt = proposal.CreatedAt
	}
	if proposal.Revision == 0 {
		proposal.Revision = 1
	}
	if !validVerificationStatus(proposal.VerificationStatus) {
		return fmt.Errorf("unsupported verification status %q", proposal.VerificationStatus)
	}
	return nil
}

func validProposalStatus(status ProposalStatus) bool {
	switch status {
	case StatusPending, StatusApproved, StatusRejected, StatusExecuting,
		StatusCompleted, StatusFailed, StatusStale, StatusExpired:
		return true
	default:
		return false
	}
}

func validVerificationStatus(status VerificationStatus) bool {
	switch status {
	case "", VerificationStatusVerified, VerificationStatusFailed, VerificationStatusUnavailable, VerificationStatusUnverified:
		return true
	default:
		return false
	}
}

func newCreateAudit(proposal *Proposal) AuditEvent {
	return normalizeAuditEvent(AuditEvent{Type: AuditEventCreate, Actor: proposal.CreatedBy}, proposal, "", StatusPending)
}

func normalizeAuditEvent(event AuditEvent, proposal *Proposal, from, to ProposalStatus) AuditEvent {
	if event.ID == "" {
		event.ID = fmt.Sprintf("audit-%d-%d", time.Now().UnixNano(), auditIDSequence.Add(1))
	}
	event.ProposalID = proposal.ID
	event.FromStatus = from
	event.ToStatus = to
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	redactor := sanitizer.DefaultRedactor()
	event.ID = redactor.SanitizeText(event.ID)
	event.ProposalID = redactor.SanitizeText(event.ProposalID)
	event.Actor = redactor.SanitizeText(event.Actor)
	event.Reason = redactor.SanitizeText(event.Reason)
	event.Message = redactor.SanitizeText(event.Message)
	return event
}

func sanitizeStateForStore(state proposalState) proposalState {
	copy := proposalState{Schema: state.Schema, Version: state.Version}
	copy.Proposals = make([]*Proposal, 0, len(state.Proposals))
	for _, proposal := range state.Proposals {
		copy.Proposals = append(copy.Proposals, sanitizeProposalForStore(proposal))
	}
	copy.Audit = cloneAuditEvents(state.Audit)
	for index := range copy.Audit {
		copy.Audit[index] = sanitizeAuditEvent(copy.Audit[index])
	}
	return copy
}

func sanitizeProposalForStore(proposal *Proposal) *Proposal {
	copy := cloneProposal(proposal)
	if copy == nil {
		return nil
	}
	redactor := sanitizer.DefaultRedactor()
	copy.ID = redactor.SanitizeText(copy.ID)
	copy.IssueID = redactor.SanitizeText(copy.IssueID)
	copy.CreatedBy = redactor.SanitizeText(copy.CreatedBy)
	copy.Namespace = redactor.SanitizeText(copy.Namespace)
	copy.Kind = redactor.SanitizeText(copy.Kind)
	copy.Name = redactor.SanitizeText(copy.Name)
	copy.TargetUID = redactor.SanitizeText(copy.TargetUID)
	copy.TargetResourceVersion = redactor.SanitizeText(copy.TargetResourceVersion)
	copy.ApprovedBy = redactor.SanitizeText(copy.ApprovedBy)
	copy.RejectedBy = redactor.SanitizeText(copy.RejectedBy)
	copy.RejectionReason = redactor.SanitizeText(copy.RejectionReason)
	copy.ExecutionResult = redactor.SanitizeText(copy.ExecutionResult)
	copy.ExecutionError = redactor.SanitizeText(copy.ExecutionError)
	copy.VerificationError = sanitizeAndBoundVerificationError(redactor, copy.VerificationError)
	if copy.Diagnosis != nil {
		copy.Diagnosis = copy.Diagnosis.SanitizedWithRedactor(redactor).AsDiagnosis()
	}
	return copy
}

func sanitizeAuditEvent(event AuditEvent) AuditEvent {
	return normalizeAuditEvent(event, &Proposal{ID: event.ProposalID}, event.FromStatus, event.ToStatus)
}

func cloneState(state proposalState) proposalState {
	copy := proposalState{Schema: state.Schema, Version: state.Version}
	copy.Proposals = make([]*Proposal, 0, len(state.Proposals))
	for _, proposal := range state.Proposals {
		copy.Proposals = append(copy.Proposals, cloneProposal(proposal))
	}
	copy.Audit = cloneAuditEvents(state.Audit)
	return copy
}

func cloneProposal(proposal *Proposal) *Proposal {
	if proposal == nil {
		return nil
	}
	copy := *proposal
	if proposal.Diagnosis != nil {
		diagnosis := *proposal.Diagnosis
		copy.Diagnosis = &diagnosis
	}
	if proposal.ApprovedAt != nil {
		approvedAt := *proposal.ApprovedAt
		copy.ApprovedAt = &approvedAt
	}
	if proposal.RejectedAt != nil {
		rejectedAt := *proposal.RejectedAt
		copy.RejectedAt = &rejectedAt
	}
	if proposal.ExpiresAt != nil {
		expiresAt := *proposal.ExpiresAt
		copy.ExpiresAt = &expiresAt
	}
	return &copy
}

func cloneAndSortProposals(proposals []*Proposal) []*Proposal {
	result := make([]*Proposal, 0, len(proposals))
	for _, proposal := range proposals {
		result = append(result, cloneProposal(proposal))
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func cloneAuditEvents(events []AuditEvent) []AuditEvent {
	result := make([]AuditEvent, len(events))
	copy(result, events)
	return result
}

func filterAuditEvents(events []AuditEvent, proposalID string) []AuditEvent {
	if proposalID == "" {
		return append([]AuditEvent(nil), events...)
	}
	result := make([]AuditEvent, 0)
	for _, event := range events {
		if event.ProposalID == proposalID {
			result = append(result, event)
		}
	}
	return result
}
