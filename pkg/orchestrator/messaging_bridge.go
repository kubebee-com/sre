package orchestrator

import (
	"context"
	"errors"

	"github.com/kubebee-com/sre/pkg/authorization"
	"github.com/kubebee-com/sre/pkg/identity"
	"github.com/kubebee-com/sre/pkg/messaging"
	"github.com/kubebee-com/sre/pkg/storage/postgres"
)

// messagingCommand accepts only mutations of existing scoped records. The native
// channel handler supplies a verified, explicitly mapped human principal.
func (s *Server) messagingCommand(ctx context.Context, p identity.Principal, scope identity.Scope, command messaging.Command) (result error) {
	defer func() {
		if errors.Is(result, postgres.ErrUnavailable) {
			result = errors.Join(messaging.ErrRetryable, result)
		}
	}()
	permission := authorization.Approve
	switch command.Verb {
	case "approve", "reject", "ack":
	case "answer":
		permission = authorization.Investigate
	default:
		return postgres.ErrInvalid
	}
	if err := s.config.Policy.Authorize(p, scope, permission); err != nil {
		return err
	}
	switch command.Verb {
	case "approve", "reject":
		service := s.config.Execution
		if service == nil || service.Fleet == nil || service.Fleet.DB == nil || service.Fleet.Policy == nil {
			return postgres.ErrUnavailable
		}
		if command.Verb == "approve" {
			_, err := service.Approve(ctx, p, scope, command.ID, command.Value)
			return err
		}
		_, err := service.Cancel(ctx, p, scope, command.ID)
		return err
	case "answer":
		if s.config.DB == nil {
			return postgres.ErrUnavailable
		}
		return s.config.DB.Transact(ctx, scope, func(tx *postgres.Tx) error {
			return tx.AnswerInteraction(command.ID, command.Version, command.Value, p.ID)
		})
	case "ack":
		service := s.config.Notifications
		if service == nil || service.DB == nil || service.Policy == nil {
			return postgres.ErrUnavailable
		}
		return service.Acknowledge(ctx, p, scope, command.ID)
	}
	return postgres.ErrInvalid
}
