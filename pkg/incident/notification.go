package incident

import (
	"github.com/kubebee-com/sre/pkg/identity"
	"time"
)

type Notification struct {
	Scope          identity.Scope `json:"scope"`
	ID             string         `json:"id"`
	EventID        string         `json:"event_id"`
	RouteID        string         `json:"route_id"`
	Kind           string         `json:"kind"`
	IncidentID     string         `json:"incident_id"`
	State          string         `json:"state"`
	Attempts       int            `json:"attempts"`
	CreatedAt      time.Time      `json:"created_at"`
	DeliveredAt    *time.Time     `json:"delivered_at,omitempty"`
	AcknowledgedBy string         `json:"acknowledged_by,omitempty"`
	Lease          string         `json:"-"`
}
