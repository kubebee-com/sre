// Package ownership keeps ownership in reviewed configuration, never labels.
package ownership

import (
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
)

type Application struct {
	Scope          identity.Scope `json:"scope"`
	OwnerGroup     string         `json:"owner_group"`
	ApproverGroups []string       `json:"approver_groups"`
}
type Registry struct{ applications map[string]Application }

func NewRegistry(applications []Application) (*Registry, error) {
	r := &Registry{applications: map[string]Application{}}
	for _, app := range applications {
		if app.Scope.Validate() != nil || app.OwnerGroup == "" {
			return nil, errors.New("explicit application ownership required")
		}
		if _, exists := r.applications[app.Scope.Key()]; exists {
			return nil, errors.New("conflicting application ownership")
		}
		bindings := []authorization.Binding{{Scope: app.Scope, Group: app.OwnerGroup, Role: authorization.Owner}}
		for _, group := range app.ApproverGroups {
			bindings = append(bindings, authorization.Binding{Scope: app.Scope, Group: group, Role: authorization.Approver})
		}
		if _, err := authorization.NewPolicy(bindings); err != nil {
			return nil, err
		}
		app.ApproverGroups = append([]string(nil), app.ApproverGroups...)
		r.applications[app.Scope.Key()] = app
	}
	return r, nil
}
func (r *Registry) Application(scope identity.Scope) (Application, bool) {
	if r == nil || scope.Validate() != nil {
		return Application{}, false
	}
	app, ok := r.applications[scope.Key()]
	app.ApproverGroups = append([]string(nil), app.ApproverGroups...)
	return app, ok
}
