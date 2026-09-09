package playbook

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresInvalidDSNIsSafe(t *testing.T) {
	_, err := NewPostgresCatalog(context.Background(), "postgres://db-user:db-password@invalid host/db")
	if !errors.Is(err, ErrCatalogUnavailable) || strings.Contains(err.Error(), "db-password") || strings.Contains(err.Error(), "invalid host") {
		t.Fatalf("unsafe error: %v", err)
	}
}
func TestPostgresCanceledStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := NewPostgresCatalog(ctx, "postgres://localhost:1/unreachable")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("startup cancellation: %v", err)
	}
}
func TestPostgresCatalogContract(t *testing.T) {
	dsn := os.Getenv("SRE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SRE_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := NewPostgresCatalog(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	catalogContract(t, c)
}
