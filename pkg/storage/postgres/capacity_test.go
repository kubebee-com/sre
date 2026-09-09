package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
)

// This opt-in measurement checks results on every read. It intentionally has no
// latency assertion: a shared CI host cannot establish a production latency SLO.
func TestEnterpriseCapacity(t *testing.T) {
	if os.Getenv("SRE_ENTERPRISE_CAPACITY") != "1" {
		t.Skip("bounded capacity measurement is opt-in")
	}
	db := database(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.SetAuthorityEpoch("capacity-epoch"); err != nil {
		t.Fatal(err)
	}
	org := identity.NewID()
	scopes := []identity.Scope{{OrganizationID: org, ClusterID: "cluster-a", ApplicationID: "app"}, {OrganizationID: org, ClusterID: "cluster-b", ApplicationID: "app"}}
	started := time.Now()
	for scopeIndex, scope := range scopes {
		for n := 0; n < 500+scopeIndex; n++ {
			err := db.Transact(ctx, scope, func(tx *Tx) error {
				id := fmt.Sprintf("incident-%04d", n)
				if err := tx.CreateIncident(incident.Incident{Scope: scope, ID: id, Version: 1, State: "OPEN", OpenedAt: now}); err != nil {
					return err
				}
				if n == 0 {
					_, err := tx.db.Exec(tx.ctx, `INSERT INTO enterprise_core.agents VALUES($1,$2,$3,'collector','COLLECTOR','sre-evidence','capacity-epoch',1,'synthetic-cluster-uid','synthetic-token-hash',$4,false)`, tx.args(now.Add(time.Hour))...)
					if err != nil {
						return err
					}
				}
				evidenceID := fmt.Sprintf("evidence-%04d", n)
				e := incident.Item{Scope: scope, IncidentID: id, ID: evidenceID, Version: 1, Kind: incident.Evidence, Body: json.RawMessage(`{"code":"POD_FAILED","source":{"agent_id":"collector","epoch":"capacity-epoch","generation":1}}`), ObservedAt: now, ValidUntil: now.Add(time.Hour)}
				if err := tx.PutItem(e); err != nil {
					return err
				}
				runID := fmt.Sprintf("run-%04d", n)
				if err := tx.StartRun(runID, id, "offline", "1", "1", "1", now); err != nil {
					return err
				}
				body, _ := json.Marshal(map[string]any{"run_id": runID, "assessment": map[string]string{"status": "NEEDS_EVIDENCE"}})
				c := incident.Item{Scope: scope, IncidentID: id, ID: fmt.Sprintf("claim-%04d", n), Version: 1, Kind: incident.Claim, Body: body, ObservedAt: now, ValidUntil: now.Add(time.Hour), Parents: []incident.ItemRef{{ID: evidenceID, Version: 1}}}
				if err := tx.PutItem(c); err != nil {
					return err
				}
				ref := incident.ItemRef{ID: c.ID, Version: 1}
				if err := tx.FinishRun(runID, "COMPLETED", "NEEDS_EVIDENCE", &ref); err != nil {
					return err
				}
				if scopeIndex == 1 && n == 0 {
					return tx.Quarantine(incident.ItemRef{ID: evidenceID, Version: 1})
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("fixture: 2 scopes, 1001 incidents, 2002 items, 1001 runs, 1001 lineage edges; seed=%s", time.Since(started))
	for _, operation := range []string{"quality", "operations", "current-evidence-and-eligibility"} {
		durations := make([]time.Duration, 0, 40)
		for iteration := 0; iteration < 21; iteration++ {
			for index, scope := range scopes {
				start := time.Now()
				err := db.Transact(ctx, scope, func(tx *Tx) error {
					switch operation {
					case "quality":
						rows, err := tx.QualityRuns(now.Add(-time.Hour))
						if err != nil {
							return err
						}
						if len(rows) != 500+index {
							return fmt.Errorf("quality scope count: got %d", len(rows))
						}
						invalid := 0
						for _, row := range rows {
							if row.Invalidated {
								invalid++
							}
							if row.Status != "COMPLETED" || row.Corroborated {
								return fmt.Errorf("incorrect run result")
							}
						}
						if invalid != index {
							return fmt.Errorf("quality quarantine crossed scope: %d", invalid)
						}
					case "operations":
						snapshot, err := tx.OperationalSnapshot(now)
						if err != nil {
							return err
						}
						if snapshot.FreshEvidence != int64(500+index) || snapshot.QuarantinedItems != int64(index) || snapshot.Agents["CURRENT"] != 1 {
							return fmt.Errorf("incorrect scoped operations counts: %+v", snapshot)
						}
					default:
						rows, err := tx.CurrentEvidence("incident-0000", now, 64)
						if err != nil {
							return err
						}
						if len(rows) != 1 || rows[0].Scope != scope {
							return fmt.Errorf("incorrect scoped evidence")
						}
						eligible, err := tx.Eligible(incident.ItemRef{ID: rows[0].ID, Version: rows[0].Version}, now)
						if err != nil {
							return err
						}
						if eligible != (index == 0) {
							return fmt.Errorf("quarantine eligibility crossed scope")
						}
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if iteration > 0 {
					durations = append(durations, time.Since(start))
				}
			}
		}
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		t.Logf("%s: samples=%d serial transactions warm p50=%s p95=%s max=%s", operation, len(durations), durations[19], durations[37], durations[39])
	}
}
