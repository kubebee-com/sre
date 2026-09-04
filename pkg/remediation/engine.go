package remediation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
	"github.com/kubebee-com/sre/pkg/triage"
	"k8s.io/client-go/kubernetes"
)

type ProposalStatus string

const (
	StatusPending   ProposalStatus = "PENDING_APPROVAL"
	StatusApproved  ProposalStatus = "APPROVED"
	StatusRejected  ProposalStatus = "REJECTED"
	StatusExecuting ProposalStatus = "EXECUTING"
	StatusCompleted ProposalStatus = "COMPLETED"
	StatusFailed    ProposalStatus = "FAILED"
)

type Proposal struct {
	ID              string           `json:"id"`
	IssueID         string           `json:"issue_id"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
	Namespace       string           `json:"namespace"`
	Kind            string           `json:"kind"`
	Name            string           `json:"name"`
	Diagnosis       *triage.Diagnosis `json:"diagnosis"`
	Status          ProposalStatus   `json:"status"`
	ApprovedBy      string           `json:"approved_by,omitempty"`
	ApprovedAt      *time.Time       `json:"approved_at,omitempty"`
	RejectedBy      string           `json:"rejected_by,omitempty"`
	RejectedAt      *time.Time       `json:"rejected_at,omitempty"`
	ExecutionResult string           `json:"execution_result,omitempty"`
	ExecutionError  string           `json:"execution_error,omitempty"`
}

type Engine struct {
	client    kubernetes.Interface
	executor  *Executor
	mu        sync.RWMutex
	proposals map[string]*Proposal
}

func NewEngine(client kubernetes.Interface) *Engine {
	return &Engine{
		client:    client,
		executor:  NewExecutor(client),
		proposals: make(map[string]*Proposal),
	}
}

func (e *Engine) CreateProposal(issue *scanner.Issue, diag *triage.Diagnosis) *Proposal {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Dedup: if active proposal exists for this issue, return existing
	for _, p := range e.proposals {
		if p.IssueID == issue.ID && (p.Status == StatusPending || p.Status == StatusExecuting) {
			return p
		}
	}

	id := fmt.Sprintf("prop-%d", time.Now().UnixNano()/1e6)
	now := time.Now()
	p := &Proposal{
		ID:        id,
		IssueID:   issue.ID,
		CreatedAt: now,
		UpdatedAt: now,
		Namespace: issue.Namespace,
		Kind:      issue.Kind,
		Name:      issue.Name,
		Diagnosis: diag,
		Status:    StatusPending, // MUST START AS PENDING APPROVAL
	}
	e.proposals[id] = p
	return p
}

func (e *Engine) ListProposals() []*Proposal {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]*Proposal, 0, len(e.proposals))
	for _, p := range e.proposals {
		list = append(list, p)
	}
	return list
}

func (e *Engine) GetProposal(id string) (*Proposal, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	p, ok := e.proposals[id]
	return p, ok
}

// Approve marks proposal as approved and asynchronously executes the safe remediation
func (e *Engine) Approve(ctx context.Context, id, approvedBy string) (*Proposal, error) {
	e.mu.Lock()
	p, ok := e.proposals[id]
	if !ok {
		e.mu.Unlock()
		return nil, errors.New("proposal not found")
	}

	if p.Status != StatusPending {
		e.mu.Unlock()
		return nil, fmt.Errorf("proposal is in status '%s', cannot approve", p.Status)
	}

	now := time.Now()
	p.Status = StatusApproved
	p.ApprovedBy = approvedBy
	p.ApprovedAt = &now
	p.UpdatedAt = now
	e.mu.Unlock()

	// Execute remediation asynchronously
	go e.executeRemediation(context.Background(), p)

	return p, nil
}

// Reject rejects the proposal with reason
func (e *Engine) Reject(id, rejectedBy string) (*Proposal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	p, ok := e.proposals[id]
	if !ok {
		return nil, errors.New("proposal not found")
	}

	if p.Status != StatusPending {
		return nil, fmt.Errorf("proposal is in status '%s', cannot reject", p.Status)
	}

	now := time.Now()
	p.Status = StatusRejected
	p.RejectedBy = rejectedBy
	p.RejectedAt = &now
	p.UpdatedAt = now
	return p, nil
}

func (e *Engine) executeRemediation(ctx context.Context, p *Proposal) {
	e.mu.Lock()
	p.Status = StatusExecuting
	p.UpdatedAt = time.Now()
	e.mu.Unlock()

	result, err := e.executor.Execute(ctx, p)

	e.mu.Lock()
	defer e.mu.Unlock()
	p.UpdatedAt = time.Now()
	p.ExecutionResult = result

	if err != nil {
		p.Status = StatusFailed
		p.ExecutionError = err.Error()
	} else {
		p.Status = StatusCompleted
	}
}
