package playbook

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"
)

func expectCatalogWrite(mock pgxmock.PgxPoolIface) {
	mock.ExpectBeginTx(pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	mock.ExpectExec("SET LOCAL statement_timeout").WillReturnResult(pgxmock.NewResult("SET", 0))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(catalogWriteLock).WillReturnResult(pgxmock.NewResult("SELECT", 1))
}

type sanitizedSQLPayload struct{}

func (sanitizedSQLPayload) Match(value any) bool {
	data, ok := value.([]byte)
	return ok && strings.Contains(string(data), "[REDACTED]") && !strings.Contains(string(data), "db-password")
}
func TestPostgresSourceWriteIsTransactionalAndSanitized(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[fail], func(t *testing.T) {
			mock, err := pgxmock.NewPool()
			if err != nil {
				t.Fatal(err)
			}
			defer mock.Close()
			c := newCatalog(&postgresBackend{pool: mock}, []CatalogOption{WithCatalogSecrets("db-password")})
			expectCatalogWrite(mock)
			mock.ExpectQuery("SELECT .* FROM playbook_catalog.sources WHERE lookup_key").WithArgs(SourceChecksum("inspect [REDACTED]")).WillReturnError(pgx.ErrNoRows)
			mock.ExpectQuery("SELECT .* FROM playbook_catalog.sources WHERE id").WithArgs("source", 0).WillReturnError(pgx.ErrNoRows)
			insert := mock.ExpectExec("INSERT INTO playbook_catalog.sources").WithArgs("source", 0, SourceChecksum("inspect [REDACTED]"), LifecycleState(""), pgxmock.AnyArg(), sanitizedSQLPayload{})
			if fail {
				insert.WillReturnError(&pgconn.PgError{Code: "XX000", Message: "postgres://user:db-password@host/db"})
				mock.ExpectRollback()
			} else {
				insert.WillReturnResult(pgxmock.NewResult("INSERT", 1))
				mock.ExpectCommit()
				mock.ExpectRollback()
			}
			err = c.SaveSource(context.Background(), SourceArtifact{ID: "source", Kind: "markdown", Origin: "upload", MediaType: "text/plain", ParserVersion: "v1", SanitizedContent: "inspect db-password"})
			if fail && !errors.Is(err, ErrCatalogUnavailable) || !fail && err != nil {
				t.Fatalf("save error: %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestPostgresTransitionUpdatesOnlyLifecycleAndAuditsActor(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()
	c := newCatalog(&postgresBackend{pool: mock}, nil)
	p := catalogFixture("pb")
	row, _ := rowFor(p.ID, p.Version, "", LifecycleReview, p)
	expectCatalogWrite(mock)
	mock.ExpectQuery("SELECT .* FROM playbook_catalog.playbooks WHERE id").WithArgs("pb", 1).WillReturnRows(pgxmock.NewRows([]string{"id", "version", "lookup_key", "state", "content_hash", "payload"}).AddRow(row.ID, row.Version, row.Lookup, row.State, row.Hash, row.Payload))
	mock.ExpectExec("INSERT INTO playbook_catalog.approvals").WithArgs(catalogTupleID("pb", "ACTIVE"), 1, "pb", LifecycleState(""), pgxmock.AnyArg(), pgxmock.AnyArg()).WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mock.ExpectExec("UPDATE playbook_catalog.playbooks SET state=\\$3 WHERE id=\\$1 AND version=\\$2").WithArgs("pb", 1, LifecycleActive).WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mock.ExpectCommit()
	mock.ExpectRollback()
	if err := c.Transition(context.Background(), "pb", 1, LifecycleActive, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestPostgresNeverInterpolatesIdentifiersOrReturnsDatabaseDetails(t *testing.T) {
	if _, err := catalogTable("playbooks; DROP TABLE sources"); !errors.Is(err, ErrCatalogInvalid) {
		t.Fatal(err)
	}
	for _, err := range []error{errors.New("password raw"), &pgconn.PgError{Code: "23505", Detail: "password raw"}, &pgconn.PgError{Code: "22000", Message: "password raw"}} {
		if strings.Contains(safeDatabaseError(err).Error(), "password") {
			t.Fatal("raw database error exposed")
		}
	}
}
