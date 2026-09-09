package environment

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
)

func Validate(c incident.EnvironmentContext) error {
	if c.Scope.Validate() != nil || c.Version < 1 || len(c.Dependencies) > 32 || len(c.Integrations) > 8 {
		return postgres.ErrInvalid
	}
	choices := map[string][]string{"environment": {"PRODUCTION", "STAGING", "DEVELOPMENT"}, "platform": {"EKS", "GKE", "AKS", "OPENSHIFT", "SELF_MANAGED", "OTHER"}, "topology": {"SINGLE_ZONE", "MULTI_ZONE", "MULTI_REGION", "UNKNOWN"}, "criticality": {"LOW", "MEDIUM", "HIGH", "CRITICAL"}}
	values := map[string]string{"environment": c.Environment, "platform": c.Platform, "topology": c.Topology, "criticality": c.Criticality}
	for key, value := range values {
		found := false
		for _, option := range choices[key] {
			if value == option {
				found = true
			}
		}
		if !found {
			return postgres.ErrInvalid
		}
	}
	seen := map[string]bool{}
	for _, d := range c.Dependencies {
		if d.Validate() != nil || d == c.Scope || d.OrganizationID != c.Scope.OrganizationID || seen[d.Key()] {
			return postgres.ErrInvalid
		}
		seen[d.Key()] = true
	}
	seen = map[string]bool{}
	for _, i := range c.Integrations {
		if seen[i] || (i != "PROMETHEUS" && i != "OPENTELEMETRY" && i != "SERVICE_MESH" && i != "GITOPS" && i != "EXTERNAL_DATABASE" && i != "EXTERNAL_QUEUE") {
			return postgres.ErrInvalid
		}
		seen[i] = true
	}
	return nil
}

type Service struct {
	DB     *postgres.Store
	Policy *authorization.Policy
}

func (s *Service) Set(ctx context.Context, p identity.Principal, c incident.EnvironmentContext) error {
	if err := s.Policy.Authorize(p, c.Scope, authorization.Setup); err != nil {
		return err
	}
	if Validate(c) != nil {
		return postgres.ErrInvalid
	}
	for _, d := range c.Dependencies {
		if s.Policy.Authorize(p, d, authorization.Setup) != nil {
			return authorization.ErrForbidden
		}
	}
	return s.DB.Transact(ctx, c.Scope, func(tx *postgres.Tx) error {
		old, err := tx.EnvironmentContext()
		if err == nil {
			if c.Version != old.Version+1 {
				return postgres.ErrConflict
			}
		} else if !errors.Is(err, postgres.ErrNotFound) {
			return err
		} else if c.Version != 1 {
			return postgres.ErrConflict
		}
		return tx.PutEnvironmentContext(c)
	})
}
