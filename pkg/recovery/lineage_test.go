package recovery

import (
	"context"
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEveryRequiredRecoverySampleIsChecked(t *testing.T) {
	dsn := os.Getenv("SRE_ENTERPRISE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("real database required")
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := identity.Scope{OrganizationID: identity.NewID(), ClusterID: "c", ApplicationID: "a"}
	at := time.Now().UTC()
	handle := strings.Repeat("a", 32)
	if err := db.Transact(ctx, scope, func(tx *postgres.Tx) error {
		if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: "i", Version: 1, State: "OPEN", OpenedAt: at.Add(-time.Hour)}); err != nil {
			return err
		}
		if err := tx.PutRecoveryProfile(incident.RecoveryProfile{Scope: scope, ID: "application-health", Version: 1, Handles: []string{handle}, WindowSeconds: 60, MaximumGapSeconds: 120, MinimumSamples: 100, MinimumReadyReplicas: 1}); err != nil {
			return err
		}
		for n := int64(1); n <= 100; n++ {
			when := at.Add(time.Duration(n-100) * time.Second)
			ref := incident.ItemRef{ID: "sample", Version: n}
			if err := tx.PutItem(incident.Item{Scope: scope, IncidentID: "i", ID: ref.ID, Version: n, Kind: incident.Evidence, Body: json.RawMessage(`{"code":"HEALTHY"}`), ObservedAt: when, ValidUntil: at.Add(time.Minute)}); err != nil {
				return err
			}
			if err := tx.PutHealthSample(incident.HealthSample{Scope: scope, IncidentID: "i", Evidence: ref, Handle: handle, UID: "u", AgentID: "collector", Generation: 1, Epoch: "epoch", Coverage: "COMPLETE", Healthy: true, ReadyReplicas: 1, At: when}); err != nil {
				return err
			}
		}
		first, err := AssessTx(tx, scope, "i", "application-health", at)
		if err != nil {
			return err
		}
		if first.Status != "RECOVERED" || len(first.Evidence) != 100 {
			t.Fatal("required prefix not recorded", first.Status, len(first.Evidence))
		}
		if err := tx.Quarantine(incident.ItemRef{ID: "sample", Version: 1}); err != nil {
			return err
		}
		second, err := AssessTx(tx, scope, "i", "application-health", at)
		if err == nil && (second.Status != "UNKNOWN" || second.Reason != "DISPUTED_HEALTH_EVIDENCE") {
			t.Fatal("disputed required sample accepted", second)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
