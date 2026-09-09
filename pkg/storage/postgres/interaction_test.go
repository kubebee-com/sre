package postgres

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/interaction"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInteractionAtomicResponseAndScope(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	scope := testScope()
	r := interaction.Request{Scope: scope, ID: "question", IncidentID: "incident", Kind: interaction.Clarification, Question: "IMPACT", Version: 1, Status: "PENDING", ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Transact(ctx, scope, func(tx *Tx) error {
		if err := tx.CreateIncident(testIncident(scope)); err != nil {
			return err
		}
		return tx.CreateInteraction(r, "owner")
	}); err != nil {
		t.Fatal(err)
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.Transact(ctx, scope, func(tx *Tx) error { return tx.AnswerInteraction("question", 1, "UNKNOWN", "human") })
			if err == nil {
				won.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("responses committed: %d", won.Load())
	}
	if err := db.Transact(ctx, scope, func(tx *Tx) error {
		values, err := tx.InteractionContext("incident")
		if err != nil {
			return err
		}
		if len(values) != 1 || values[0].Question != "IMPACT" || values[0].Answer != "UNKNOWN" {
			t.Fatalf("answer not available for diagnosis: %+v", values)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Transact(ctx, testScope(), func(tx *Tx) error { return tx.AnswerInteraction("question", 1, "UNKNOWN", "human") }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scope: %v", err)
	}
}
func TestInteractionExpiryAndAnswerValidation(t *testing.T) {
	db := database(t)
	ctx := context.Background()
	scope := testScope()
	r := interaction.Request{Scope: scope, ID: "question", IncidentID: "incident", Kind: interaction.Clarification, Question: "IMPACT", Version: 1, Status: "PENDING", ExpiresAt: time.Now().Add(time.Hour)}
	if err := db.Transact(ctx, scope, func(tx *Tx) error {
		if err := tx.CreateIncident(testIncident(scope)); err != nil {
			return err
		}
		return tx.CreateInteraction(r, "owner")
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *Tx) error { return tx.AnswerInteraction("question", 1, "yes", "human") }); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *Tx) error {
		_, err := tx.db.Exec(ctx, "UPDATE enterprise_core.interactions SET expires_at=now()-interval '1 second' WHERE "+scopeWhere, tx.args()...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Transact(ctx, scope, func(tx *Tx) error { return tx.AnswerInteraction("question", 1, "UNKNOWN", "human") }); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired answered: %v", err)
	}
}
