package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrAuthCapacity = errors.New("authentication capacity reached")

type authExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// Serialize cleanup and admission per auth table across all replicas.
func (s *Store) createAuthRecord(ctx context.Context, table string, insert func(context.Context, authExecutor) error) error {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "sre-auth-"+table); err != nil {
		return safeError(err)
	}
	// table is a private constant supplied only by the two typed creation methods.
	if _, err = tx.Exec(ctx, `DELETE FROM enterprise_core.`+table+` WHERE expires_at<=clock_timestamp()`); err != nil {
		return safeError(err)
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM enterprise_core.`+table).Scan(&count); err != nil {
		return safeError(err)
	}
	if count >= 1000 {
		return ErrAuthCapacity
	}
	if err = insert(ctx, tx); err != nil {
		return safeError(err)
	}
	return safeError(tx.Commit(ctx))
}
