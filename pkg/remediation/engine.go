package remediation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	"k8s.io/client-go/kubernetes"
)

const (
	defaultExecutionTimeout       = 30 * time.Second
	defaultVerificationTimeout    = 30 * time.Second
	defaultOutcomeObserverTimeout = 5 * time.Second
	defaultProposalTTL            = 15 * time.Minute
	defaultWorkerCount            = 1
	defaultQueueSize              = 128
	internalProposalActor         = "scanner"
	engineActor                   = "remediation-engine"
	maxExecutionErrorBytes        = 512
)

var proposalIDSequence atomic.Uint64

type Proposal struct {
	ID                    string             `json:"id"`
	IssueID               string             `json:"issue_id"`
	CreatedBy             string             `json:"created_by"`
	CreatedAt             time.Time          `json:"created_at"`
	UpdatedAt             time.Time          `json:"updated_at"`
	Namespace             string             `json:"namespace"`
	Kind                  string             `json:"kind"`
	Name                  string             `json:"name"`
	TargetUID             string             `json:"target_uid,omitempty"`
	TargetResourceVersion string             `json:"target_resource_version,omitempty"`
	Revision              uint64             `json:"revision"`
	ExpiresAt             *time.Time         `json:"expires_at,omitempty"`
	Diagnosis             *triage.Diagnosis  `json:"diagnosis"`
	Status                ProposalStatus     `json:"status"`
	ApprovedBy            string             `json:"approved_by,omitempty"`
	ApprovedAt            *time.Time         `json:"approved_at,omitempty"`
	RejectedBy            string             `json:"rejected_by,omitempty"`
	RejectedAt            *time.Time         `json:"rejected_at,omitempty"`
	RejectionReason       string             `json:"rejection_reason,omitempty"`
	ExecutionResult       string             `json:"execution_result,omitempty"`
	ExecutionError        string             `json:"execution_error,omitempty"`
	VerificationStatus    VerificationStatus `json:"verification_status,omitempty"`
	VerificationError     string             `json:"verification_error,omitempty"`
	rolloutGeneration     int64
	rolloutBaselineSet    bool
}

type ProposalExecutor interface {
	Execute(context.Context, *Proposal) (string, error)
}

type VerificationStatus string

const (
	VerificationStatusVerified    VerificationStatus = "VERIFIED"
	VerificationStatusFailed      VerificationStatus = "FAILED"
	VerificationStatusUnavailable VerificationStatus = "UNAVAILABLE"
	VerificationStatusUnverified  VerificationStatus = "UNVERIFIED"
)

type VerificationResult struct {
	Status  VerificationStatus
	Message string
}

type ProposalVerifier interface {
	Verify(context.Context, *Proposal) (VerificationResult, error)
}

type OutcomeObserver interface {
	ObserveOutcome(context.Context, *Proposal) error
}

type proposalValidator interface {
	Validate(context.Context, *Proposal) error
}

type EngineOptions struct {
	Store            ProposalStore
	Executor         ProposalExecutor
	WorkerCount      int
	QueueSize        int
	ExecutionTimeout time.Duration
	ProposalTTL      time.Duration
}

// EngineVerificationOptions configures the optional verification and learning
// lane without changing the legacy EngineOptions field layout. Non-positive
// timeouts use bounded defaults.
type EngineVerificationOptions struct {
	Verifier               ProposalVerifier
	OutcomeObserver        OutcomeObserver
	TerminalObserver       OutcomeObserver // Best-effort audit of every durable terminal transition.
	VerificationTimeout    time.Duration
	OutcomeObserverTimeout time.Duration
}

type Engine struct {
	persistenceErrors      atomic.Uint64
	store                  ProposalStore
	executor               ProposalExecutor
	verifier               ProposalVerifier
	outcomeObserver        OutcomeObserver
	terminalObserver       OutcomeObserver
	terminalSlots          chan struct{}
	outcomeSlots           chan struct{}
	workerContext          context.Context
	workerCancel           context.CancelFunc
	queue                  chan string
	workers                sync.WaitGroup
	createMu               sync.Mutex
	closeOnce              sync.Once
	closed                 chan struct{}
	executionTimeout       time.Duration
	verificationTimeout    time.Duration
	outcomeObserverTimeout time.Duration
	proposalTTL            time.Duration
	closeErr               error
}

func NewEngine(client kubernetes.Interface) *Engine {
	return NewEngineWithOptions(client, EngineOptions{})
}

func NewEngineWithStore(client kubernetes.Interface, store ProposalStore) *Engine {
	return NewEngineWithOptions(client, EngineOptions{Store: store})
}

func NewEngineWithOptions(client kubernetes.Interface, options EngineOptions) *Engine {
	return NewEngineWithVerificationOptions(client, options, EngineVerificationOptions{})
}

// NewEngineWithVerificationOptions constructs an engine with explicit outcome
// verification and observation behavior.
func NewEngineWithVerificationOptions(client kubernetes.Interface, options EngineOptions, verificationOptions EngineVerificationOptions) *Engine {
	store := options.Store
	if store == nil {
		store = NewMemoryProposalStore()
	}
	executor := options.Executor
	if executor == nil {
		executor = NewExecutor(client)
	}
	verifier := verificationOptions.Verifier
	if verifier == nil {
		if executorVerifier, ok := executor.(ProposalVerifier); ok {
			verifier = executorVerifier
		}
	}
	workerCount := options.WorkerCount
	if workerCount <= 0 {
		workerCount = defaultWorkerCount
	}
	queueSize := options.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	executionTimeout := options.ExecutionTimeout
	if executionTimeout <= 0 {
		executionTimeout = defaultExecutionTimeout
	}
	proposalTTL := options.ProposalTTL
	if proposalTTL <= 0 {
		proposalTTL = defaultProposalTTL
	}
	verificationTimeout := verificationOptions.VerificationTimeout
	if verificationTimeout <= 0 {
		verificationTimeout = defaultVerificationTimeout
	}
	outcomeObserverTimeout := verificationOptions.OutcomeObserverTimeout
	if outcomeObserverTimeout <= 0 {
		outcomeObserverTimeout = defaultOutcomeObserverTimeout
	}
	workerContext, workerCancel := context.WithCancel(context.Background())
	engine := &Engine{
		store:                  store,
		executor:               executor,
		verifier:               verifier,
		outcomeObserver:        verificationOptions.OutcomeObserver,
		terminalObserver:       verificationOptions.TerminalObserver,
		terminalSlots:          make(chan struct{}, 4),
		outcomeSlots:           make(chan struct{}, 4),
		workerContext:          workerContext,
		workerCancel:           workerCancel,
		queue:                  make(chan string, queueSize),
		closed:                 make(chan struct{}),
		executionTimeout:       executionTimeout,
		verificationTimeout:    verificationTimeout,
		outcomeObserverTimeout: outcomeObserverTimeout,
		proposalTTL:            proposalTTL,
	}
	engine.startWorkers(workerCount)
	engine.recoverApprovedWork()
	return engine
}

func (e *Engine) startWorkers(count int) {
	for index := 0; index < count; index++ {
		e.workers.Add(1)
		go e.worker()
	}
}

func (e *Engine) recoverApprovedWork() {
	proposals, err := e.store.List()
	if err != nil {
		return
	}
	for _, proposal := range proposals {
		if proposalExpired(proposal, time.Now().UTC()) {
			switch proposal.Status {
			case StatusPending:
				_, _ = e.transition(proposal.ID, StatusPending, StatusExpired, func(updated *Proposal) error {
					updated.ExecutionError = safeExecutionError(ErrProposalExpired)
					return nil
				}, AuditEvent{Type: AuditEventExpire, Actor: engineActor, Message: safeExecutionError(ErrProposalExpired)})
			case StatusApproved:
				_, _ = e.transition(proposal.ID, StatusApproved, StatusExpired, func(updated *Proposal) error {
					updated.ExecutionError = safeExecutionError(ErrProposalExpired)
					return nil
				}, AuditEvent{Type: AuditEventExpire, Actor: engineActor, Message: safeExecutionError(ErrProposalExpired)})
			}
			continue
		}
		switch proposal.Status {
		case StatusApproved:
			e.enqueue(proposal.ID, nil)
		case StatusExecuting:
			// A process cannot prove whether an interrupted mutation completed.
			// Keep the durable record failed and require reconciliation rather than
			// replaying a potentially destructive action automatically.
			_, _ = e.transition(proposal.ID, StatusExecuting, StatusFailed, func(updated *Proposal) error {
				updated.ExecutionError = "execution interrupted; reconciliation required"
				return nil
			}, AuditEvent{Type: AuditEventFailure, Actor: engineActor, Message: "execution interrupted; reconciliation required"})
		}
	}
}

// CreateProposal keeps the historical internal scanner API. External callers
// should use CreateProposalForActor so the authenticated actor is explicit.
func (e *Engine) CreateProposal(issue *scanner.Issue, diag *triage.Diagnosis) *Proposal {
	proposal, _ := e.CreateProposalForActor(issue, diag, internalProposalActor)
	return proposal
}

func (e *Engine) CreateProposalForActor(issue *scanner.Issue, diag *triage.Diagnosis, actor string) (*Proposal, error) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return nil, ErrActorRequired
	}
	if issue == nil || triage.ValidateDiagnosis(diag, issue.ID) != nil {
		return nil, errors.New("invalid proposal diagnosis")
	}
	if proposalTargetsRequired(diag.ActionType) && (strings.TrimSpace(issue.TargetUID) == "" || strings.TrimSpace(issue.TargetResourceVersion) == "") {
		return nil, ErrMissingPrecondition
	}

	e.createMu.Lock()
	defer e.createMu.Unlock()
	proposals, err := e.store.List()
	if err != nil {
		return nil, fmt.Errorf("list proposals: %w", err)
	}
	for _, existing := range proposals {
		if existing.IssueID == issue.ID && isActiveProposalStatus(existing.Status) {
			return existing, nil
		}
	}

	now := time.Now().UTC()
	proposal := &Proposal{
		ID:                    newProposalID(),
		IssueID:               issue.ID,
		CreatedBy:             actor,
		CreatedAt:             now,
		UpdatedAt:             now,
		Namespace:             issue.Namespace,
		Kind:                  issue.Kind,
		Name:                  issue.Name,
		TargetUID:             issue.TargetUID,
		TargetResourceVersion: issue.TargetResourceVersion,
		Revision:              1,
		Diagnosis:             cloneDiagnosis(diag),
		Status:                StatusPending,
	}
	expiresAt := now.Add(e.proposalTTL)
	proposal.ExpiresAt = &expiresAt
	if err := e.store.Create(proposal); err != nil {
		return nil, fmt.Errorf("create proposal: %w", err)
	}
	return e.store.Get(proposal.ID)
}

// PersistenceErrors reports failed durable state transitions, without raw errors.
func (e *Engine) PersistenceErrors() uint64 { return e.persistenceErrors.Load() }

func (e *Engine) ListProposalsWithError() ([]*Proposal, error) { return e.store.List() }

func (e *Engine) ListProposals() []*Proposal {
	proposals, err := e.store.List()
	if err != nil {
		return nil
	}
	return proposals
}

func (e *Engine) GetProposal(id string) (*Proposal, bool) {
	proposal, err := e.store.Get(id)
	return proposal, err == nil
}

func (e *Engine) ListAuditEvents(proposalID string) ([]AuditEvent, error) {
	return e.store.ListAuditEvents(proposalID)
}

// Approve durably records the approval before queueing execution. The target
// is validated once here and again immediately before the worker mutates it.
func (e *Engine) Approve(ctx context.Context, id, approvedBy string) (*Proposal, error) {
	approvedBy = strings.TrimSpace(approvedBy)
	if approvedBy == "" {
		return nil, ErrActorRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	proposal, err := e.store.Get(id)
	if err != nil {
		return nil, err
	}
	if proposalExpired(proposal, time.Now().UTC()) {
		expired, transitionErr := e.transition(id, StatusPending, StatusExpired, func(updated *Proposal) error {
			updated.ExecutionError = safeExecutionError(ErrProposalExpired)
			return nil
		}, AuditEvent{Type: AuditEventExpire, Actor: approvedBy, Message: safeExecutionError(ErrProposalExpired)})
		if transitionErr != nil {
			return nil, ErrProposalExpired
		}
		return expired, ErrProposalExpired
	}
	if proposal.Diagnosis != nil && proposalTargetsRequired(proposal.Diagnosis.ActionType) && (strings.TrimSpace(proposal.TargetUID) == "" || strings.TrimSpace(proposal.TargetResourceVersion) == "") {
		stale, transitionErr := e.transition(id, StatusPending, StatusStale, func(updated *Proposal) error {
			updated.ExecutionError = safeExecutionError(ErrMissingPrecondition)
			return nil
		}, AuditEvent{Type: AuditEventStale, Actor: approvedBy, Message: safeExecutionError(ErrMissingPrecondition)})
		if transitionErr != nil {
			return nil, ErrMissingPrecondition
		}
		return stale, ErrMissingPrecondition
	}
	if validator, ok := e.executor.(proposalValidator); ok {
		if err := validator.Validate(ctx, proposal); err != nil {
			if errors.Is(err, ErrStalePrecondition) || errors.Is(err, ErrMissingPrecondition) {
				stale, transitionErr := e.transition(id, StatusPending, StatusStale, func(updated *Proposal) error {
					updated.ExecutionError = safeExecutionError(err)
					return nil
				}, AuditEvent{Type: AuditEventStale, Actor: approvedBy, Message: safeExecutionError(err)})
				if transitionErr != nil {
					return nil, err
				}
				return stale, err
			}
			if errors.Is(err, ErrProtectedTarget) || errors.Is(err, ErrForceDeletion) {
				rejected, transitionErr := e.transition(id, StatusPending, StatusRejected, func(updated *Proposal) error {
					updated.RejectionReason = safeExecutionError(err)
					updated.ExecutionError = safeExecutionError(err)
					return nil
				}, AuditEvent{Type: AuditEventReject, Actor: approvedBy, Reason: safeExecutionError(err)})
				if transitionErr != nil {
					return nil, err
				}
				return rejected, err
			}
			return nil, err
		}
	}

	now := time.Now().UTC()
	approved, err := e.transition(id, StatusPending, StatusApproved, func(updated *Proposal) error {
		updated.ApprovedBy = approvedBy
		updated.ApprovedAt = &now
		return nil
	}, AuditEvent{Type: AuditEventApprove, Actor: approvedBy})
	if err != nil {
		return nil, err
	}
	// An approval remains durable even if the request context is cancelled.
	// The context only controls how long this call waits to enqueue the work.
	if err := e.enqueue(id, ctx); err != nil {
		return approved, err
	}
	return approved, nil
}

// Reject rejects the proposal with an optional reason.
func (e *Engine) Reject(id, rejectedBy string, reasons ...string) (*Proposal, error) {
	rejectedBy = strings.TrimSpace(rejectedBy)
	if rejectedBy == "" {
		return nil, ErrActorRequired
	}
	proposal, err := e.store.Get(id)
	if err != nil {
		return nil, err
	}
	if proposalExpired(proposal, time.Now().UTC()) {
		expired, transitionErr := e.transition(id, StatusPending, StatusExpired, func(updated *Proposal) error {
			updated.ExecutionError = safeExecutionError(ErrProposalExpired)
			return nil
		}, AuditEvent{Type: AuditEventExpire, Actor: rejectedBy, Message: safeExecutionError(ErrProposalExpired)})
		if transitionErr != nil {
			return nil, ErrProposalExpired
		}
		return expired, ErrProposalExpired
	}
	now := time.Now().UTC()
	return e.transition(id, StatusPending, StatusRejected, func(updated *Proposal) error {
		updated.RejectedBy = rejectedBy
		updated.RejectedAt = &now
		if len(reasons) > 0 {
			updated.RejectionReason = strings.TrimSpace(reasons[0])
		}
		return nil
	}, AuditEvent{Type: AuditEventReject, Actor: rejectedBy, Reason: firstReason(reasons)})
}

func (e *Engine) enqueue(id string, ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-e.closed:
		return errors.New("remediation engine is closed")
	case e.queue <- id:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) worker() {
	defer e.workers.Done()
	for {
		select {
		case <-e.workerContext.Done():
			return
		case id := <-e.queue:
			e.executeProposal(id)
		}
	}
}

func (e *Engine) executeProposal(id string) {
	proposal, err := e.store.Get(id)
	if err != nil || proposal.Status != StatusApproved {
		return
	}
	if proposalExpired(proposal, time.Now().UTC()) {
		_, _ = e.transition(id, StatusApproved, StatusExpired, func(updated *Proposal) error {
			updated.ExecutionError = safeExecutionError(ErrProposalExpired)
			return nil
		}, AuditEvent{Type: AuditEventExpire, Actor: engineActor, Message: safeExecutionError(ErrProposalExpired)})
		return
	}
	executing, err := e.transition(id, StatusApproved, StatusExecuting, nil, AuditEvent{Type: AuditEventExecution, Actor: engineActor, Message: "execution started"})
	if err != nil {
		return
	}
	executionContext, cancelExecution := context.WithTimeout(e.workerContext, e.executionTimeout)
	result, executionErr := e.executor.Execute(executionContext, executing)
	cancelExecution()
	if executionErr != nil {
		e.finishExecution(id, executionErr, result)
		return
	}
	verificationContext, cancelVerification := context.WithTimeout(e.workerContext, e.verificationTimeout)
	completed, verified := e.finishVerifiedExecution(verificationContext, id, executing, result)
	cancelVerification()
	if verified && proposalSupportsLearningOutcome(completed) && e.outcomeObserver != nil {
		e.scheduleOutcome(completed)
	}
}

func (e *Engine) finishExecution(id string, executionErr error, result string) {
	if errors.Is(executionErr, ErrStalePrecondition) || errors.Is(executionErr, ErrMissingPrecondition) {
		_, _ = e.transition(id, StatusExecuting, StatusStale, func(updated *Proposal) error {
			updated.ExecutionResult = sanitizer.DefaultRedactor().SanitizeText(result)
			updated.ExecutionError = safeExecutionError(executionErr)
			return nil
		}, AuditEvent{Type: AuditEventStale, Actor: engineActor, Message: safeExecutionError(executionErr)})
		return
	}
	message := safeExecutionError(executionErr)
	_, _ = e.transition(id, StatusExecuting, StatusFailed, func(updated *Proposal) error {
		updated.ExecutionResult = sanitizer.DefaultRedactor().SanitizeText(result)
		updated.ExecutionError = message
		return nil
	}, AuditEvent{Type: AuditEventFailure, Actor: engineActor, Message: message})
}

func (e *Engine) finishVerifiedExecution(ctx context.Context, id string, proposal *Proposal, result string) (*Proposal, bool) {
	if !proposalSupportsLearningOutcome(proposal) {
		completed, _ := e.completeExecution(id, result, VerificationStatusUnverified, "")
		return completed, false
	}
	if e.verifier == nil {
		completed, _ := e.completeExecution(id, result, VerificationStatusUnavailable, "verification is unavailable")
		return completed, false
	}
	verification, err := e.verifier.Verify(ctx, proposal)
	if err != nil {
		verification = VerificationResult{Status: VerificationStatusUnavailable, Message: err.Error()}
	}
	verification = normalizeVerificationResult(verification)
	if verification.Status == VerificationStatusVerified || verification.Status == VerificationStatusUnverified {
		completed, err := e.completeExecution(id, result, verification.Status, "")
		return completed, err == nil && verification.Status == VerificationStatusVerified
	}

	message := safeVerificationError(verification.Message)
	completed, _ := e.completeExecution(id, result, verification.Status, message)
	return completed, false
}

func proposalSupportsLearningOutcome(proposal *Proposal) bool {
	if proposal == nil || proposal.Diagnosis == nil {
		return false
	}
	switch proposal.Diagnosis.ActionType {
	case triage.ActionRestartPod, triage.ActionDeleteFailedPod, triage.ActionCleanupPods,
		triage.ActionRolloutRestart, triage.ActionCordonNode, triage.ActionScaleWorkload,
		triage.ActionBumpVersion, triage.ActionUpgradeApp:
		return true
	default:
		return false
	}
}

func (e *Engine) scheduleOutcome(proposal *Proposal) {
	// Observers are best effort: a context-ignoring callback retains its slot
	// until it actually returns, without blocking execution workers or Close.
	select {
	case e.outcomeSlots <- struct{}{}:
	default:
		return
	}

	observer := e.outcomeObserver
	observedProposal := cloneProposal(proposal)
	timeout := e.outcomeObserverTimeout
	go func() {
		defer func() { <-e.outcomeSlots }()
		defer func() { _ = recover() }()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_ = observer.ObserveOutcome(ctx, observedProposal)
	}()
}

func (e *Engine) completeExecution(id, result string, verificationStatus VerificationStatus, verificationError string) (*Proposal, error) {
	return e.transition(id, StatusExecuting, StatusCompleted, func(updated *Proposal) error {
		updated.ExecutionResult = sanitizer.DefaultRedactor().SanitizeText(result)
		updated.ExecutionError = ""
		updated.VerificationStatus = verificationStatus
		updated.VerificationError = sanitizeAndBoundVerificationError(sanitizer.DefaultRedactor(), verificationError)
		return nil
	}, AuditEvent{Type: AuditEventExecution, Actor: engineActor, Message: "execution completed"})
}

func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		close(e.closed)
		e.workerCancel()
		e.workers.Wait()
		if e.store != nil {
			e.closeErr = e.store.Close()
		}
	})
	return e.closeErr
}

func isActiveProposalStatus(status ProposalStatus) bool {
	return status == StatusPending || status == StatusApproved || status == StatusExecuting
}

func proposalTargetsRequired(action triage.ActionType) bool {
	switch action {
	case triage.ActionRestartPod, triage.ActionDeleteFailedPod, triage.ActionCleanupPods,
		triage.ActionRolloutRestart, triage.ActionCordonNode, triage.ActionScaleWorkload,
		triage.ActionBumpVersion, triage.ActionUpgradeApp:
		return true
	default:
		return false
	}
}

func proposalExpired(proposal *Proposal, now time.Time) bool {
	return proposal != nil && proposal.ExpiresAt != nil && !now.Before(proposal.ExpiresAt.UTC())
}

func newProposalID() string {
	sequence := proposalIDSequence.Add(1)
	var random [8]byte
	if _, err := rand.Read(random[:]); err == nil {
		return fmt.Sprintf("prop-%d-%d-%s", time.Now().UnixNano(), sequence, hex.EncodeToString(random[:]))
	}
	return fmt.Sprintf("prop-%d-%d", time.Now().UnixNano(), sequence)
}

func cloneDiagnosis(diagnosis *triage.Diagnosis) *triage.Diagnosis {
	if diagnosis == nil {
		return nil
	}
	copy := *diagnosis
	return &copy
}

func firstReason(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return reasons[0]
}

func safeExecutionError(err error) string {
	if err == nil {
		return ""
	}
	message := sanitizer.DefaultRedactor().SafeLogValue(err.Error())
	if len(message) > maxExecutionErrorBytes {
		message = message[:maxExecutionErrorBytes]
	}
	return message
}

func normalizeVerificationResult(result VerificationResult) VerificationResult {
	switch result.Status {
	case VerificationStatusVerified:
		result.Message = ""
	case VerificationStatusFailed:
		if strings.TrimSpace(result.Message) == "" {
			result.Message = "verification failed"
		}
	case VerificationStatusUnavailable:
		if strings.TrimSpace(result.Message) == "" {
			result.Message = "verification is unavailable"
		}
	case VerificationStatusUnverified:
		result.Message = ""
	default:
		result.Status = VerificationStatusUnavailable
		if strings.TrimSpace(result.Message) == "" {
			result.Message = "verification returned an unsupported status"
		}
	}
	return result
}

func safeVerificationError(message string) string {
	message = sanitizer.DefaultRedactor().SafeLogValue(message)
	if strings.TrimSpace(message) == "" {
		message = "verification failed"
	}
	if len(message) > maxExecutionErrorBytes {
		message = message[:maxExecutionErrorBytes]
	}
	return message
}
