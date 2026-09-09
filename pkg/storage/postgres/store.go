// Package postgres is the scoped orchestrator state authority. It has no file fallback.
package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kubebee-com/sre/pkg/identity"
	"strings"
	"sync/atomic"
	"time"
)

var (
	ErrUnavailable = errors.New("orchestrator storage unavailable")
	ErrConflict    = errors.New("orchestrator state conflict")
	ErrNotFound    = errors.New("orchestrator record not found")
	ErrInvalid     = errors.New("invalid orchestrator record")
)

//go:embed migrations/*.sql
var migrations embed.FS

const operationTimeout = 10 * time.Second
const migrationLock int64 = 736728194202700

type Store struct {
	pool  *pgxpool.Pool
	epoch atomic.Value
}

func Open(ctx context.Context, dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, ErrUnavailable
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, ErrUnavailable
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, ErrUnavailable
	}
	store := &Store{pool: pool}
	if err = store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func safeError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		switch pgerr.Code {
		case "23505", "40001", "40P01":
			return ErrConflict
		case "23503", "23514", "22P02":
			return ErrInvalid
		}
	}
	return ErrUnavailable
}
func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return safeError(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", migrationLock); err != nil {
		return safeError(err)
	}
	if _, err = tx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS enterprise_core; CREATE TABLE IF NOT EXISTS enterprise_core.migrations(version integer PRIMARY KEY, checksum text NOT NULL)`); err != nil {
		return safeError(err)
	}
	files, err := migrations.ReadDir("migrations")
	if err != nil {
		return ErrUnavailable
	}
	type migration struct {
		data     []byte
		checksum string
	}
	known := make([]migration, len(files))
	for n, file := range files {
		expected := fmt.Sprintf("%03d_", n+1)
		if !strings.HasPrefix(file.Name(), expected) || !strings.HasSuffix(file.Name(), ".sql") {
			return ErrConflict
		}
		data, err := migrations.ReadFile("migrations/" + file.Name())
		if err != nil {
			return ErrUnavailable
		}
		digest := sha256.Sum256(data)
		known[n] = migration{data: data, checksum: hex.EncodeToString(digest[:])}
	}
	rows, err := tx.Query(ctx, "SELECT version,checksum FROM enterprise_core.migrations ORDER BY version")
	if err != nil {
		return safeError(err)
	}
	applied := 0
	for rows.Next() {
		var version int
		var checksum string
		if err = rows.Scan(&version, &checksum); err != nil {
			rows.Close()
			return safeError(err)
		}
		if version != applied+1 || version > len(known) || checksum != known[version-1].checksum {
			rows.Close()
			return ErrConflict
		}
		applied++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return safeError(err)
	}
	for n := applied; n < len(known); n++ {
		if _, err = tx.Exec(ctx, string(known[n].data)); err != nil {
			return safeError(err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO enterprise_core.migrations(version,checksum) VALUES($1,$2)", n+1, known[n].checksum); err != nil {
			return safeError(err)
		}
	}

	return safeError(tx.Commit(ctx))
}

func (s *Store) SetAuthorityEpoch(epoch string) error {
	if !identity.ValidID(epoch) {
		return ErrInvalid
	}
	s.epoch.Store(epoch)
	return nil
}
func (s *Store) authorityEpoch() string {
	value := s.epoch.Load()
	if value == nil {
		return ""
	}
	return value.(string)
}
