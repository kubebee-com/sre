// Package feedback records attributed assessments without promoting them to truth.
package feedback

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"sort"
	"time"
)

type Request struct {
	IncidentID     string              `json:"incident_id"`
	Item           incident.ItemRef    `json:"item"`
	ItemHash       string              `json:"item_hash"`
	Assessment     incident.Assessment `json:"assessment"`
	ReasonCode     string              `json:"reason_code,omitempty"`
	Evidence       []incident.ItemRef  `json:"evidence,omitempty"`
	Supersedes     string              `json:"supersedes,omitempty"`
	IdempotencyKey string              `json:"idempotency_key"`
}
type Service struct {
	DB     *postgres.Store
	Policy *authorization.Policy
}

func validReason(code string) bool {
	switch code {
	case "", "FACTUAL_ERROR", "NOT_APPLICABLE", "STALE", "MISSING_EVIDENCE", "CONTRADICTED", "CONFIRMED", "UNRESOLVED":
		return true
	}
	return false
}
func (s *Service) Submit(ctx context.Context, principal identity.Principal, scope identity.Scope, request Request) (incident.FeedbackEvent, error) {
	if err := s.Policy.Authorize(principal, scope, authorization.Feedback); err != nil {
		return incident.FeedbackEvent{}, err
	}
	if s.DB == nil {
		return incident.FeedbackEvent{}, postgres.ErrUnavailable
	}
	if !identity.ValidID(request.IncidentID) || !identity.ValidID(request.Item.ID) || request.Item.Version < 1 || !identity.ValidID(request.IdempotencyKey) || len(request.ItemHash) != 64 || !validReason(request.ReasonCode) || len(request.Evidence) > 32 {
		return incident.FeedbackEvent{}, postgres.ErrInvalid
	}
	// Idempotency keys are opaque correlation inputs, never persisted as engineer text.
	keyDigest := sha256.Sum256([]byte(request.IdempotencyKey))
	request.IdempotencyKey = hex.EncodeToString(keyDigest[:])
	switch request.Assessment {
	case incident.True, incident.False, incident.CannotVerify:
	default:
		return incident.FeedbackEvent{}, postgres.ErrInvalid
	}
	request.Evidence = append([]incident.ItemRef{}, request.Evidence...)
	sort.Slice(request.Evidence, func(i, j int) bool {
		if request.Evidence[i].ID == request.Evidence[j].ID {
			return request.Evidence[i].Version < request.Evidence[j].Version
		}
		return request.Evidence[i].ID < request.Evidence[j].ID
	})
	for n, ref := range request.Evidence {
		if !identity.ValidID(ref.ID) || ref.Version < 1 || (n > 0 && ref == request.Evidence[n-1]) {
			return incident.FeedbackEvent{}, postgres.ErrInvalid
		}
	}
	raw, _ := json.Marshal(request)
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	var result incident.FeedbackEvent
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		previous, err := tx.FeedbackForKey(principal.ID, request.IdempotencyKey)
		if err == nil {
			if previous.RequestHash != hash {
				return postgres.ErrConflict
			}
			result = previous
			return nil
		}
		if !errors.Is(err, postgres.ErrNotFound) {
			return err
		}
		item, err := tx.CurrentItem(request.Item.ID)
		if err != nil {
			return err
		}
		if item.IncidentID != request.IncidentID || item.Version != request.Item.Version || item.Hash != request.ItemHash {
			return postgres.ErrConflict
		}
		for _, ref := range request.Evidence {
			evidence, err := tx.Item(ref)
			if err != nil {
				return err
			}
			if evidence.IncidentID != item.IncidentID {
				return postgres.ErrInvalid
			}
		}
		if request.Supersedes != "" {
			previous, err := tx.FeedbackByID(request.Supersedes)
			if err != nil {
				return err
			}
			if previous.ActorID != principal.ID || previous.Item != request.Item {
				return postgres.ErrConflict
			}
		}
		result = incident.FeedbackEvent{Scope: scope, IncidentID: item.IncidentID, ID: identity.NewID(), ActorID: principal.ID, Item: request.Item, ItemHash: item.Hash, Assessment: request.Assessment, ReasonCode: request.ReasonCode, Evidence: request.Evidence, Supersedes: request.Supersedes, IdempotencyKey: request.IdempotencyKey, RequestHash: hash, At: time.Now().UTC()}
		if err := tx.AddFeedback(result); err != nil {
			return err
		}
		if result.Assessment == incident.False {
			if err := tx.Quarantine(result.Item); err != nil {
				return err
			}
		}
		payload, _ := json.Marshal(map[string]string{"event_id": result.ID, "incident_id": item.IncidentID})
		return tx.Enqueue(result.ID, "FEEDBACK_RECORDED", payload)
	})
	return result, err
}
