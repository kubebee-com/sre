package postgres

import (
	"context"
	"github.com/jackc/pgx/v5/pgconn"
)

// OpenSecure requires certificate/hostname verification on every connection path.
func OpenSecure(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil || cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify {
		return nil, ErrUnavailable
	}
	for _, fallback := range cfg.Fallbacks {
		if fallback.TLSConfig == nil || fallback.TLSConfig.InsecureSkipVerify {
			return nil, ErrUnavailable
		}
	}
	return Open(ctx, dsn)
}
func (s *Store) Ready(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return ErrUnavailable
	}
	return safeError(s.pool.Ping(ctx))
}
