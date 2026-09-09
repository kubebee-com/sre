package postgres

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/incident"
)

// UNION bounds traversal even if a corrupted import introduced a cycle. Historical
// provenance retains disputes and source revocation without requiring old facts to
// masquerade as currently fresh evidence.
const lineageSQL = `WITH RECURSIVE edges AS (
 SELECT child_id,child_version,parent_id,parent_version,false historic FROM enterprise_core.item_parents WHERE ` + scopeWhere + `
 UNION ALL SELECT child_id,child_version,parent_id,parent_version,true historic FROM enterprise_core.historical_dependencies WHERE ` + scopeWhere + `
), lineage(id,version,historic) AS (
 SELECT id,version,false FROM enterprise_core.items WHERE ` + scopeWhere + ` AND id=$4 AND version=$5
 UNION SELECT p.parent_id,p.parent_version,l.historic OR p.historic FROM edges p JOIN lineage l ON p.child_id=l.id AND p.child_version=l.version
)`

func (t *Tx) linkGuidance(item incident.Item) error {
	if item.Kind != incident.Claim {
		return nil
	}
	var body struct {
		Knowledge []incident.ItemRef `json:"knowledge_versions"`
	}
	if json.Unmarshal(item.Body, &body) != nil || len(body.Knowledge) > 16 {
		return ErrInvalid
	}
	for _, ref := range body.Knowledge {
		g, err := t.GoldenCase(ref.ID)
		if err != nil {
			return err
		}
		if g.Version != ref.Version || g.State != "ACTIVE" {
			return ErrConflict
		}
		recovery, err := t.RecoveryAssessment(g.RecoveryID)
		if err != nil {
			return err
		}
		refs := append([]incident.ItemRef{g.Claim}, recovery.Evidence...)
		for _, parent := range refs {
			if parent.ID == item.ID {
				return ErrInvalid
			}
			if _, err := t.Item(parent); err != nil {
				return err
			}
			_, err = t.db.Exec(t.ctx, `INSERT INTO enterprise_core.historical_dependencies VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, t.args(item.ID, item.Version, parent.ID, parent.Version)...)
			if err != nil {
				return safeError(err)
			}
		}
	}
	return nil
}
