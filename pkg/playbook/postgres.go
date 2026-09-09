package playbook

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var catalogMigrations embed.FS

const catalogOperationTimeout = 10 * time.Second
const catalogMigrationTimeout = 30 * time.Second
const catalogWriteLock int64 = 736728194202601
const catalogMigrationLock int64 = 736728194202602

// PostgresCatalog owns a bounded pgx pool. Close it after callers stop using it.
type PostgresCatalog struct {
	*catalog
	pool *pgxpool.Pool
}

func NewPostgresCatalog(ctx context.Context, dsn string, options ...CatalogOption) (*PostgresCatalog, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, ErrCatalogUnavailable
	}
	cfg.MaxConns = 4
	cfg.MinConns = 0
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	startup, cancel := context.WithTimeout(ctx, catalogOperationTimeout)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(startup, cfg)
	if err != nil {
		return nil, ErrCatalogUnavailable
	}
	if err = pool.Ping(startup); err != nil {
		pool.Close()
		return nil, safeDatabaseError(err)
	}
	if err = migrateCatalog(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	// Include parsed credentials as literals in addition to structural redaction.
	options = append([]CatalogOption{WithCatalogSecrets(dsn, cfg.ConnConfig.Password)}, options...)
	return &PostgresCatalog{catalog: newCatalog(&postgresBackend{pool: pool}, options), pool: pool}, nil
}
func (c *PostgresCatalog) Close() {
	if c != nil && c.pool != nil {
		c.pool.Close()
	}
}
func migrateCatalog(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, catalogMigrationTimeout)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return safeDatabaseError(err)
	}
	defer rollbackCatalog(tx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", catalogMigrationLock); err != nil {
		return safeDatabaseError(err)
	}
	if _, err = tx.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS playbook_catalog; CREATE TABLE IF NOT EXISTS playbook_catalog.schema_migrations (name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())"); err != nil {
		return safeDatabaseError(err)
	}
	names, err := fs.Glob(catalogMigrations, "migrations/*.sql")
	if err != nil {
		return ErrCatalogUnavailable
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := catalogMigrations.ReadFile(name)
		if err != nil {
			return ErrCatalogUnavailable
		}
		checksum := SourceChecksum(string(data))
		var stored string
		err = tx.QueryRow(ctx, "SELECT checksum FROM playbook_catalog.schema_migrations WHERE name=$1", name).Scan(&stored)
		if err == nil {
			if stored != checksum {
				return ErrCatalogConflict
			}
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return safeDatabaseError(err)
		}
		if _, err = tx.Exec(ctx, string(data)); err != nil {
			return safeDatabaseError(err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO playbook_catalog.schema_migrations(name,checksum) VALUES ($1,$2)", name, checksum); err != nil {
			return safeDatabaseError(err)
		}
	}
	return safeDatabaseError(tx.Commit(ctx))
}
func rollbackCatalog(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func safeDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCatalogNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrCatalogConflict
	}
	return ErrCatalogUnavailable
}

type postgresBackend struct {
	pool interface {
		BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	}
}

func (b *postgresBackend) read(ctx context.Context, fn func(catalogTx) error) error {
	return b.transact(ctx, false, fn)
}
func (b *postgresBackend) write(ctx context.Context, fn func(catalogTx) error) error {
	return b.transact(ctx, true, fn)
}
func (b *postgresBackend) transact(ctx context.Context, write bool, fn func(catalogTx) error) error {
	ctx, cancel := context.WithTimeout(ctx, catalogOperationTimeout)
	defer cancel()
	options := pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
	if write {
		options = pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite}
	}
	tx, err := b.pool.BeginTx(ctx, options)
	if err != nil {
		return safeDatabaseError(err)
	}
	defer rollbackCatalog(tx)
	if _, err = tx.Exec(ctx, "SET LOCAL statement_timeout = '10s'; SET LOCAL lock_timeout = '5s'"); err != nil {
		return safeDatabaseError(err)
	}
	// All catalog writers share this transaction lock. Reads use MVCC snapshots,
	// and independent processes see atomic source/candidate deduplication.
	if write {
		if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", catalogWriteLock); err != nil {
			return safeDatabaseError(err)
		}
	}
	if err = fn(&postgresTx{tx}); err != nil {
		return err
	}
	return safeDatabaseError(tx.Commit(ctx))
}

type postgresTx struct{ tx pgx.Tx }

func catalogTable(table string) (string, error) {
	switch table {
	case "sources", "digests", "playbooks", "steps", "bindings", "findings", "evidence_snapshots", "resolution_runs", "resolution_steps", "approvals", "feedback", "relations", "learning_candidates":
		return "playbook_catalog." + table, nil
	}
	return "", ErrCatalogInvalid
}

const catalogColumns = "id, version, lookup_key, state, content_hash, payload"

func scanCatalogRow(row pgx.Row) (out catalogRow, err error) {
	err = row.Scan(&out.ID, &out.Version, &out.Lookup, &out.State, &out.Hash, &out.Payload)
	return out, safeDatabaseError(err)
}
func (t *postgresTx) get(ctx context.Context, table, id string, version int) (catalogRow, error) {
	name, err := catalogTable(table)
	if err != nil {
		return catalogRow{}, err
	}
	return scanCatalogRow(t.tx.QueryRow(ctx, "SELECT "+catalogColumns+" FROM "+name+" WHERE id=$1 AND version=$2", id, version))
}
func (t *postgresTx) lookup(ctx context.Context, table, key string) (catalogRow, error) {
	name, err := catalogTable(table)
	if err != nil {
		return catalogRow{}, err
	}
	return scanCatalogRow(t.tx.QueryRow(ctx, "SELECT "+catalogColumns+" FROM "+name+" WHERE lookup_key=$1 ORDER BY id,version LIMIT 1", key))
}
func (t *postgresTx) each(ctx context.Context, table string, state LifecycleState, fn func(catalogRow) (bool, error)) error {
	name, err := catalogTable(table)
	if err != nil {
		return err
	}
	query := "SELECT " + catalogColumns + " FROM " + name
	var args []any
	if state != "" {
		query += " WHERE state=$1"
		args = append(args, state)
	}
	query += " ORDER BY id,version"
	rows, err := t.tx.Query(ctx, query, args...)
	if err != nil {
		return safeDatabaseError(err)
	}
	defer rows.Close()
	for rows.Next() {
		row, err := scanCatalogRow(rows)
		if err != nil {
			return err
		}
		more, err := fn(row)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
	return safeDatabaseError(rows.Err())
}
func (t *postgresTx) insert(ctx context.Context, table string, row catalogRow) error {
	name, err := catalogTable(table)
	if err != nil {
		return err
	}
	_, err = t.tx.Exec(ctx, "INSERT INTO "+name+" ("+catalogColumns+") VALUES ($1,$2,$3,$4,$5,$6::jsonb)", row.ID, row.Version, row.Lookup, row.State, row.Hash, row.Payload)
	return safeDatabaseError(err)
}
func (t *postgresTx) state(ctx context.Context, id string, version int, state LifecycleState) error {
	tag, err := t.tx.Exec(ctx, "UPDATE playbook_catalog.playbooks SET state=$3 WHERE id=$1 AND version=$2", id, version, state)
	if err != nil {
		return safeDatabaseError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrCatalogNotFound
	}
	return nil
}
func (t *postgresTx) count(ctx context.Context, table string, state LifecycleState) (int, error) {
	name, err := catalogTable(table)
	if err != nil {
		return 0, err
	}
	query := "SELECT count(*) FROM " + name
	var args []any
	if state != "" {
		query += " WHERE state=$1"
		args = append(args, state)
	}
	var count int
	err = t.tx.QueryRow(ctx, query, args...).Scan(&count)
	return count, safeDatabaseError(err)
}

var _ Catalog = (*PostgresCatalog)(nil)

func (t *postgresTx) replaceFinding(ctx context.Context, row catalogRow) error {
	_, err := t.tx.Exec(ctx, "INSERT INTO playbook_catalog.findings ("+catalogColumns+") VALUES ($1,0,$2,$3,$4,$5::jsonb) ON CONFLICT (id,version) DO UPDATE SET payload=EXCLUDED.payload,content_hash=EXCLUDED.content_hash", row.ID, row.Lookup, row.State, row.Hash, row.Payload)
	return safeDatabaseError(err)
}
