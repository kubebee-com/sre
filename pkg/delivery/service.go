package delivery

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/incident"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
	"os"
	"time"
)

type Route struct {
	ID                   string         `json:"id"`
	Scope                identity.Scope `json:"scope"`
	RecipientGroup       string         `json:"recipient_group"`
	EndpointEnv          string         `json:"endpoint_env,omitempty"`
	Channel              *Channel       `json:"channel,omitempty"`
	EscalationRouteID    string         `json:"escalation_route_id,omitempty"`
	EscalateAfterSeconds int            `json:"escalate_after_seconds,omitempty"`
}
type Sender interface {
	Send(context.Context, string, incident.Notification) error
}
type ChannelSender interface {
	SendChannel(context.Context, Channel, incident.Notification) error
}

type Service struct {
	DB                *postgres.Store
	Policy            *authorization.Policy
	routes            []Route
	sender            Sender
	escalationTargets map[string]bool
}

func NewService(db *postgres.Store, policy *authorization.Policy, routes []Route, sender Sender) (*Service, error) {
	if db == nil || policy == nil || len(routes) > 1000 {
		return nil, ErrDelivery
	}
	if sender == nil {
		sender = NewHTTPSender()
	}
	ids := map[string]Route{}
	copied := append([]Route(nil), routes...)
	for i := range copied {
		if copied[i].Channel != nil {
			channel := *copied[i].Channel
			copied[i].Channel = &channel
		}
	}
	for _, r := range copied {
		if !identity.ValidID(r.ID) || r.Scope.Validate() != nil || r.RecipientGroup == "" {
			return nil, ErrDelivery
		}
		if _, exists := ids[r.ID]; exists {
			return nil, ErrDelivery
		}
		if r.Channel != nil {
			if r.EndpointEnv != "" || r.Channel.Validate() != nil {
				return nil, ErrDelivery
			}
			if _, ok := sender.(ChannelSender); !ok {
				return nil, ErrDelivery
			}
		} else if !identity.ValidID(r.EndpointEnv) || ValidateEndpoint(os.Getenv(r.EndpointEnv)) != nil {
			return nil, ErrDelivery
		}
		ids[r.ID] = r
	}
	for _, r := range copied {
		if r.EscalationRouteID != "" {
			next, ok := ids[r.EscalationRouteID]
			if !ok || next.Scope != r.Scope || next.ID == r.ID || next.EscalationRouteID != "" || r.EscalateAfterSeconds < 60 || r.EscalateAfterSeconds > 86400 {
				return nil, ErrDelivery
			}
		}
	}
	targets := map[string]bool{}
	for _, r := range copied {
		if r.EscalationRouteID != "" {
			targets[r.EscalationRouteID] = true
		}
	}
	return &Service{DB: db, Policy: policy, routes: copied, sender: sender, escalationTargets: targets}, nil
}
func (s *Service) recipient(r Route) identity.Principal {
	return identity.Principal{ID: r.ID, Issuer: "https://sre.internal/notification-recipient", Groups: []string{r.RecipientGroup}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
}
func (s *Service) Dispatch(ctx context.Context, r Route) error {
	if s.Policy.Authorize(s.recipient(r), r.Scope, authorization.Read) != nil {
		return authorization.ErrForbidden
	}
	var n incident.Notification
	err := s.DB.Transact(ctx, r.Scope, func(tx *postgres.Tx) error {
		if !s.escalationTargets[r.ID] {
			if err := tx.MaterializeNotifications(r.ID); err != nil {
				return err
			}
		}
		if r.EscalationRouteID != "" {
			if err := tx.EscalateNotifications(r.ID, r.EscalationRouteID, time.Duration(r.EscalateAfterSeconds)*time.Second); err != nil {
				return err
			}
		}
		var err error
		n, err = tx.LeaseNotification(r.ID)
		// No source delivery is required when only an escalation was created.
		// Commit that work instead of rolling it back with the absent lease.
		if errors.Is(err, postgres.ErrNotFound) {
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	if n.ID == "" {
		return nil
	}
	// Reauthorize the registered destination immediately before external delivery.
	if s.Policy.Authorize(s.recipient(r), r.Scope, authorization.Read) != nil {
		return authorization.ErrForbidden
	}
	delivered := s.send(ctx, r, n) == nil
	return s.DB.Transact(ctx, r.Scope, func(tx *postgres.Tx) error { return tx.FinishNotification(n, delivered) })
}
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	index := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for n := 0; n < min(4, len(s.routes)); n++ {
				route := s.routes[index%len(s.routes)]
				index++
				bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
				_ = s.Dispatch(bounded, route)
				cancel()
			}
		}
	}
}
func (s *Service) Acknowledge(ctx context.Context, p identity.Principal, scope identity.Scope, id string) error {
	if err := s.Policy.Authorize(p, scope, authorization.Approve); err != nil {
		return err
	}
	return s.DB.Transact(ctx, scope, func(tx *postgres.Tx) error { return tx.AcknowledgeNotification(id, p.ID) })
}

func (s *Service) RegisterRoutes(ctx context.Context) error {
	for _, route := range s.routes {
		if err := s.DB.Transact(ctx, route.Scope, func(tx *postgres.Tx) error { return tx.RegisterNotificationRoute(route.ID) }); err != nil {
			return err
		}
	}
	return nil
}

// send preserves the durable delivery lifecycle for both typed and generic routes.
func (s *Service) send(ctx context.Context, r Route, n incident.Notification) error {
	if r.Channel != nil {
		sender, ok := s.sender.(ChannelSender)
		if !ok {
			return ErrDelivery
		}
		return sender.SendChannel(ctx, *r.Channel, n)
	}
	return s.sender.Send(ctx, os.Getenv(r.EndpointEnv), n)
}
