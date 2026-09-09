package quality

import (
	"context"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"sort"
	"time"
)

type Cohort struct {
	Day            string  `json:"day"`
	ProfileID      string  `json:"profile_id"`
	ProfileVersion string  `json:"profile_version"`
	PromptVersion  string  `json:"prompt_version"`
	RubricVersion  string  `json:"rubric_version"`
	Metrics        Metrics `json:"metrics"`
}
type Report struct {
	Since            time.Time      `json:"since"`
	Overall          Metrics        `json:"overall"`
	Cohorts          []Cohort       `json:"cohorts"`
	RecoveryObserved map[string]int `json:"incidents_with_recovery_status"`
}
type Service struct {
	DB     *postgres.Store
	Policy *authorization.Policy
}

func (s *Service) Report(ctx context.Context, p identity.Principal, scope identity.Scope, days int) (Report, error) {
	if err := s.Policy.Authorize(p, scope, authorization.Read); err != nil {
		return Report{}, err
	}
	if days < 1 || days > 365 {
		return Report{}, postgres.ErrInvalid
	}
	report := Report{Since: time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour), Cohorts: []Cohort{}}
	err := s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
		rows, err := tx.QualityRuns(report.Since)
		if err != nil {
			return err
		}
		runs := []Run{}
		groups := map[string][]Run{}
		for _, row := range rows {
			r := Run{IncidentID: row.IncidentID, Corroborated: row.Corroborated, Invalidated: row.Invalidated, Day: row.Day, ProfileID: row.ProfileID, ProfileVersion: row.ProfileVersion, PromptVersion: row.PromptVersion, RubricVersion: row.RubricVersion, Status: row.Status, Reason: row.Reason, Reviews: row.Reviews}
			runs = append(runs, r)
			key := r.Day + "/" + r.ProfileID + "/" + r.ProfileVersion + "/" + r.PromptVersion + "/" + r.RubricVersion
			groups[key] = append(groups[key], r)
		}
		report.Overall = Aggregate(runs)
		keys := []string{}
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rs := groups[k]
			r := rs[0]
			report.Cohorts = append(report.Cohorts, Cohort{Day: r.Day, ProfileID: r.ProfileID, ProfileVersion: r.ProfileVersion, PromptVersion: r.PromptVersion, RubricVersion: r.RubricVersion, Metrics: Aggregate(rs)})
		}
		report.RecoveryObserved, err = tx.RecoveryCounts(report.Since)
		return err
	})
	return report, err
}
