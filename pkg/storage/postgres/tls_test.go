package postgres

import (
	"context"
	"testing"
)

func TestProductionStorageRejectsUnverifiedTransport(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer", "require"} {
		t.Run(mode, func(t *testing.T) {
			s, err := OpenSecure(context.Background(), "postgres://user:unused@127.0.0.1:1/test?sslmode="+mode)
			if s != nil {
				s.Close()
			}
			if err != ErrUnavailable {
				t.Fatal("unverified transport not rejected", err)
			}
		})
	}
}
