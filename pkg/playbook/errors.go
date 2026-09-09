package playbook

import "errors"

var (
	ErrInvalidIdentifier      = errors.New("playbook identifier is required")
	ErrInvalidLifecycleState  = errors.New("playbook lifecycle state is invalid")
	ErrInvalidConfidence      = errors.New("playbook confidence is out of range")
	ErrTextTooLong            = errors.New("playbook text exceeds bounds")
	ErrTooManyItems           = errors.New("playbook collection exceeds bounds")
	ErrInvalidCount           = errors.New("playbook count is out of range")
	ErrDuplicateIdentifier    = errors.New("playbook identifier is duplicated")
	ErrInvalidLearningOutcome = errors.New("playbook learning outcome is invalid")
	ErrInvalidLabelSelector   = errors.New("playbook label selector is invalid")
	ErrUnresolvedReference    = errors.New("playbook reference is unresolved")
	ErrObserveOnlyMutation    = errors.New("observe-only step cannot mutate")
	ErrUnsafeCommand          = errors.New("playbook command is unsafe")
	ErrUnknownAction          = errors.New("playbook action is unknown")
	ErrMissingRequired        = errors.New("playbook required field is missing")
)
