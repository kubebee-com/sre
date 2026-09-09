package operations

import (
	"context"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"sync/atomic"
	"time"
)

type Service struct {
	DB            *postgres.Store
	Scopes        []identity.Scope
	RetentionDays int
	Failures      atomic.Uint64
	LastSuccess   atomic.Int64
}

func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		for _, scope := range s.Scopes {
			if ctx.Err() != nil {
				return
			}
			err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.Retain(s.RetentionDays) })
			if err != nil {
				s.Failures.Add(1)
			} else {
				s.LastSuccess.Store(time.Now().Unix())
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
