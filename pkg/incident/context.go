package incident

import "github.com/kubebee-com/sre/pkg/identity"

// EnvironmentContext is administrator-supplied context, not a grant of access.
// Strict mode accepts structured choices instead of customer-bearing prose.
type EnvironmentContext struct {
	Scope        identity.Scope   `json:"scope"`
	Version      int64            `json:"version"`
	Environment  string           `json:"environment"`
	Platform     string           `json:"platform"`
	Topology     string           `json:"topology"`
	Criticality  string           `json:"criticality"`
	Dependencies []identity.Scope `json:"dependencies"`
	Integrations []string         `json:"integrations"`
}
