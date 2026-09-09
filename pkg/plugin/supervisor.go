package plugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	DefaultProcessStartupTimeout = 30 * time.Second
	DefaultProcessHealthTimeout  = 10 * time.Second
	DefaultProcessStopTimeout    = 5 * time.Second
	MaxProcessStartupTimeout     = 5 * time.Minute
	MaxProcessHealthTimeout      = 5 * time.Minute
	MaxProcessStopTimeout        = 1 * time.Minute
	processHealthRetryInitial    = 10 * time.Millisecond
	processHealthRetryMaximum    = 250 * time.Millisecond
	processKillWait              = time.Second
)

var (
	ErrProcessSupervisorUnavailable = errors.New("plugin process supervisor is unavailable")
	ErrProcessSupervisorClosed      = errors.New("plugin process supervisor is closed")
	ErrProcessSupervisorStarted     = errors.New("plugin process supervisor has already been started")
	ErrProcessSupervisorCommand     = errors.New("plugin process command is invalid")
	ErrProcessSupervisorTimeout     = errors.New("plugin process timeout is invalid")
	ErrProcessSupervisorStart       = errors.New("plugin process failed to start")
	ErrProcessSupervisorHealth      = errors.New("plugin process health check failed")
	ErrProcessSupervisorNotReady    = errors.New("plugin process is not ready")
	ErrProcessSupervisorExited      = errors.New("plugin process exited before becoming ready")
	ErrProcessSupervisorStop        = errors.New("plugin process failed to stop")
)

// CommandFactory creates an unstarted child command. The context is canceled
// when the supervisor is stopped; factories should pass it to
// exec.CommandContext. The supervisor never invokes a shell or joins command
// arguments into a command string.
type CommandFactory func(context.Context) (*exec.Cmd, error)

// ProcessSupervisorOptions configures one supervised plugin process. Exactly
// one of Command and CommandFactory must be provided. Command is an argv
// vector: its first element is the executable and the remaining elements are
// passed as arguments without shell interpretation.
type ProcessSupervisorOptions struct {
	ClientOptions Options

	Command        []string
	Environment    []string
	CommandFactory CommandFactory

	StartupTimeout time.Duration
	HealthTimeout  time.Duration
	StopTimeout    time.Duration
}

type normalizedProcessSupervisorOptions struct {
	clientOptions  Options
	command        []string
	environment    []string
	commandFactory CommandFactory
	startupTimeout time.Duration
	healthTimeout  time.Duration
	stopTimeout    time.Duration
}

type processSupervisorState uint8

const (
	processSupervisorNew processSupervisorState = iota
	processSupervisorStarting
	processSupervisorRunning
	processSupervisorStopping
	processSupervisorStopped
	processSupervisorClosed
)

type supervisedProcess struct {
	client      *Client
	cmd         *exec.Cmd
	processDone chan struct{}
	cancel      context.CancelFunc
}

// ProcessSupervisor owns one external plugin process and its Client. Start
// returns the client after the process reports ready; callers may then
// explicitly register and activate it through Registry. Stop is terminal for
// the process and client, while Close also prevents any future Start call.
type ProcessSupervisor struct {
	options normalizedProcessSupervisorOptions

	mu            sync.Mutex
	state         processSupervisorState
	operationDone chan struct{}
	startCancel   context.CancelFunc
	stopRequested bool
	run           *supervisedProcess
}

// NewProcessSupervisor validates the plugin client and process configuration
// without starting a child process or dialing the plugin.
func NewProcessSupervisor(options ProcessSupervisorOptions) (*ProcessSupervisor, error) {
	normalized, err := normalizeProcessSupervisorOptions(options)
	if err != nil {
		return nil, err
	}
	probe, err := NewClient(normalized.clientOptions)
	if err != nil {
		return nil, err
	}
	_ = probe.Close()
	return &ProcessSupervisor{options: normalized, state: processSupervisorNew}, nil
}

func normalizeProcessSupervisorOptions(options ProcessSupervisorOptions) (normalizedProcessSupervisorOptions, error) {
	if options.CommandFactory != nil && len(options.Command) > 0 {
		return normalizedProcessSupervisorOptions{}, ErrProcessSupervisorCommand
	}
	if options.CommandFactory == nil {
		if len(options.Command) == 0 || strings.TrimSpace(options.Command[0]) == "" {
			return normalizedProcessSupervisorOptions{}, ErrProcessSupervisorCommand
		}
		for _, argument := range options.Command {
			if strings.ContainsRune(argument, '\x00') {
				return normalizedProcessSupervisorOptions{}, ErrProcessSupervisorCommand
			}
		}
	}
	for _, environment := range options.Environment {
		if strings.ContainsRune(environment, '\x00') {
			return normalizedProcessSupervisorOptions{}, ErrProcessSupervisorCommand
		}
	}
	startupTimeout, err := boundedProcessTimeout(options.StartupTimeout, DefaultProcessStartupTimeout, MaxProcessStartupTimeout)
	if err != nil {
		return normalizedProcessSupervisorOptions{}, err
	}
	healthTimeout, err := boundedProcessTimeout(options.HealthTimeout, DefaultProcessHealthTimeout, MaxProcessHealthTimeout)
	if err != nil {
		return normalizedProcessSupervisorOptions{}, err
	}
	stopTimeout, err := boundedProcessTimeout(options.StopTimeout, DefaultProcessStopTimeout, MaxProcessStopTimeout)
	if err != nil {
		return normalizedProcessSupervisorOptions{}, err
	}
	clientOptions := options.ClientOptions
	if clientOptions.DialContext == nil {
		clientOptions.DialContext = dialPluginEndpoint
	}
	return normalizedProcessSupervisorOptions{
		clientOptions:  clientOptions,
		command:        append([]string(nil), options.Command...),
		environment:    append([]string(nil), options.Environment...),
		commandFactory: options.CommandFactory,
		startupTimeout: startupTimeout,
		healthTimeout:  healthTimeout,
		stopTimeout:    stopTimeout,
	}, nil
}

func dialPluginEndpoint(ctx context.Context, target string) (net.Conn, error) {
	address := target
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		address = parsed.Host
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}

func boundedProcessTimeout(value, fallback, maximum time.Duration) (time.Duration, error) {
	if value == 0 {
		return fallback, nil
	}
	if value < 0 || value > maximum {
		return 0, ErrProcessSupervisorTimeout
	}
	return value, nil
}

// Start starts the child, waits for a healthy protocol response, and returns
// the owned client. The caller's context bounds startup and health checks.
// Starting a supervisor more than once is rejected, including after Stop.
func (s *ProcessSupervisor) Start(ctx context.Context) (*Client, error) {
	if s == nil {
		return nil, ErrProcessSupervisorUnavailable
	}
	ctx = normalizeContext(ctx)

	s.mu.Lock()
	switch s.state {
	case processSupervisorClosed:
		s.mu.Unlock()
		return nil, ErrProcessSupervisorClosed
	case processSupervisorStarting, processSupervisorRunning, processSupervisorStopping, processSupervisorStopped:
		s.mu.Unlock()
		return nil, ErrProcessSupervisorStarted
	case processSupervisorNew:
		s.state = processSupervisorStarting
		s.operationDone = make(chan struct{})
	}
	operationDone := s.operationDone
	s.mu.Unlock()

	startupContext, startupCancel := context.WithTimeout(ctx, s.options.startupTimeout)
	processContext, processCancel := context.WithCancel(context.Background())
	startCancel := func() {
		startupCancel()
		processCancel()
	}

	s.mu.Lock()
	if s.state != processSupervisorStarting || s.stopRequested {
		s.mu.Unlock()
		startupCancel()
		processCancel()
		return s.finishStart(operationDone, nil, startError(startupContext.Err()))
	}
	s.startCancel = startCancel
	s.mu.Unlock()

	run, err := s.startProcess(startupContext, processContext, processCancel)
	startupCancel()
	client, startErr := s.finishStart(operationDone, run, err)
	if startErr != nil {
		processCancel()
	}
	return client, startErr
}

func (s *ProcessSupervisor) startProcess(startupContext, processContext context.Context, processCancel context.CancelFunc) (*supervisedProcess, error) {
	if err := startupContext.Err(); err != nil {
		return nil, startError(err)
	}
	client, err := NewClient(s.options.clientOptions)
	if err != nil {
		return nil, err
	}
	commandResult := make(chan struct {
		cmd *exec.Cmd
		err error
	}, 1)
	go func() {
		cmd, commandErr := s.newCommand(processContext)
		commandResult <- struct {
			cmd *exec.Cmd
			err error
		}{cmd: cmd, err: commandErr}
	}()
	var command *exec.Cmd
	select {
	case result := <-commandResult:
		command = result.cmd
		if result.err != nil {
			_ = client.Close()
			return nil, result.err
		}
	case <-startupContext.Done():
		_ = client.Close()
		return nil, startError(startupContext.Err())
	}
	if err := startupContext.Err(); err != nil {
		_ = client.Close()
		return nil, startError(err)
	}
	if err := command.Start(); err != nil {
		_ = client.Close()
		return nil, ErrProcessSupervisorStart
	}
	run := &supervisedProcess{client: client, cmd: command, processDone: make(chan struct{}), cancel: processCancel}
	go func() {
		_ = command.Wait()
		close(run.processDone)
	}()

	healthContext, healthCancel := context.WithTimeout(startupContext, s.options.healthTimeout)
	defer healthCancel()
	healthResult := make(chan struct {
		ready bool
		err   error
	}, 1)
	go func() {
		ready, healthErr := waitForHealthy(healthContext, client)
		healthResult <- struct {
			ready bool
			err   error
		}{ready: ready, err: healthErr}
	}()
	select {
	case result := <-healthResult:
		if result.err != nil {
			return run, healthError(result.err)
		}
		if !result.ready {
			return run, ErrProcessSupervisorNotReady
		}
		select {
		case <-run.processDone:
			return run, ErrProcessSupervisorExited
		default:
			return run, nil
		}
	case <-run.processDone:
		return run, ErrProcessSupervisorExited
	case <-healthContext.Done():
		return run, healthError(healthContext.Err())
	case <-startupContext.Done():
		return run, startError(startupContext.Err())
	}
}

func waitForHealthy(ctx context.Context, client *Client) (bool, error) {
	backoff := processHealthRetryInitial
	for {
		attemptContext, attemptCancel := context.WithTimeout(ctx, processHealthRetryMaximum)
		ready, _, err := client.Health(attemptContext)
		attemptCancel()
		if err == nil && ready {
			return true, nil
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if err != nil && !errors.Is(err, ErrPluginUnavailable) && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			if err == nil {
				return false, ctx.Err()
			}
			return false, err
		case <-timer.C:
		}
		if backoff < processHealthRetryMaximum {
			backoff *= 2
			if backoff > processHealthRetryMaximum {
				backoff = processHealthRetryMaximum
			}
		}
	}
}

func (s *ProcessSupervisor) newCommand(ctx context.Context) (*exec.Cmd, error) {
	if s.options.commandFactory != nil {
		command, err := s.options.commandFactory(ctx)
		if err != nil || command == nil || strings.TrimSpace(command.Path) == "" || commandHasNUL(command) {
			return nil, ErrProcessSupervisorCommand
		}
		if len(s.options.environment) > 0 {
			environment := command.Env
			if environment == nil {
				environment = os.Environ()
			}
			command.Env = append(environment, s.options.environment...)
		}
		return command, nil
	}
	command := exec.CommandContext(ctx, s.options.command[0], s.options.command[1:]...)
	if len(s.options.environment) > 0 {
		command.Env = append(os.Environ(), s.options.environment...)
	}
	return command, nil
}

func commandHasNUL(command *exec.Cmd) bool {
	if strings.ContainsRune(command.Path, '\x00') {
		return true
	}
	for _, argument := range command.Args {
		if strings.ContainsRune(argument, '\x00') {
			return true
		}
	}
	return false
}

func (s *ProcessSupervisor) finishStart(operationDone chan struct{}, run *supervisedProcess, err error) (*Client, error) {
	s.mu.Lock()
	if s.state == processSupervisorStarting && s.stopRequested && !errors.Is(err, context.Canceled) {
		err = startError(context.Canceled)
	}
	if err == nil {
		if s.state == processSupervisorStarting && !s.stopRequested {
			s.state = processSupervisorRunning
			s.run = run
			s.startCancel = nil
			close(operationDone)
			s.operationDone = nil
			s.mu.Unlock()
			return run.client, nil
		}
		if s.state == processSupervisorClosed {
			err = ErrProcessSupervisorClosed
		} else {
			err = startError(context.Canceled)
		}
	}
	s.mu.Unlock()
	if run != nil {
		s.cleanupProcess(run)
	}
	s.mu.Lock()
	if s.state != processSupervisorClosed {
		s.state = processSupervisorStopped
	}
	s.run = nil
	s.startCancel = nil
	s.stopRequested = false
	if s.operationDone == operationDone {
		close(operationDone)
		s.operationDone = nil
	}
	s.mu.Unlock()
	return nil, err
}

// Client returns the owned client only after Start has completed successfully.
// The returned client is invalid after Stop or Close.
func (s *ProcessSupervisor) Client() *Client {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != processSupervisorRunning || s.run == nil {
		return nil
	}
	return s.run.client
}

// Stop terminates the child and closes its client. It is safe to call before
// Start, after a failed Start, and repeatedly. If Start is in progress, Stop
// cancels it and waits for its cleanup, bounded by ctx.
func (s *ProcessSupervisor) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	ctx = normalizeContext(ctx)
	s.mu.Lock()
	switch s.state {
	case processSupervisorNew, processSupervisorStopped, processSupervisorClosed:
		s.mu.Unlock()
		return nil
	case processSupervisorStarting:
		s.stopRequested = true
		cancel := s.startCancel
		done := s.operationDone
		s.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		waitContext, waitCancel := context.WithTimeout(ctx, s.options.stopTimeout)
		defer waitCancel()
		return waitForOperation(waitContext, done)
	case processSupervisorStopping:
		done := s.operationDone
		s.mu.Unlock()
		return waitForOperation(ctx, done)
	case processSupervisorRunning:
		s.state = processSupervisorStopping
		done := make(chan struct{})
		s.operationDone = done
		run := s.run
		s.mu.Unlock()

		err := s.stopProcess(ctx, run)
		s.mu.Lock()
		if s.operationDone == done {
			if s.state != processSupervisorClosed {
				s.state = processSupervisorStopped
			}
			s.run = nil
			s.operationDone = nil
			close(done)
		}
		s.mu.Unlock()
		return err
	default:
		s.mu.Unlock()
		return ErrProcessSupervisorUnavailable
	}
}

func waitForOperation(ctx context.Context, done <-chan struct{}) error {
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *ProcessSupervisor) stopProcess(ctx context.Context, run *supervisedProcess) error {
	if run == nil {
		return nil
	}
	_ = run.client.Close()
	stopContext, stopCancel := context.WithTimeout(ctx, s.options.stopTimeout)
	defer stopCancel()
	select {
	case <-run.processDone:
		return nil
	default:
	}
	if run.cmd != nil && run.cmd.Process != nil {
		if err := run.cmd.Process.Signal(os.Interrupt); err != nil {
			_ = run.cmd.Process.Kill()
		}
	}
	select {
	case <-run.processDone:
		if ctx.Err() != nil {
			return processStopError(ctx, stopContext)
		}
		return nil
	case <-stopContext.Done():
		if run.cancel != nil {
			run.cancel()
		}
		if run.cmd != nil && run.cmd.Process != nil {
			_ = run.cmd.Process.Kill()
		}
		select {
		case <-run.processDone:
			if ctx.Err() != nil {
				return processStopError(ctx, stopContext)
			}
			return nil
		case <-time.After(processKillWait):
			return processStopError(ctx, stopContext)
		}
	}
}

func (s *ProcessSupervisor) cleanupProcess(run *supervisedProcess) {
	if run == nil {
		return
	}
	if run.cancel != nil {
		run.cancel()
	}
	_ = run.client.Close()
	if run.cmd == nil || run.cmd.Process == nil {
		return
	}
	select {
	case <-run.processDone:
		return
	default:
		_ = run.cmd.Process.Kill()
	}
	select {
	case <-run.processDone:
	case <-time.After(processKillWait):
	}
}

// Close stops the process if necessary and makes the supervisor permanently
// unusable. It is safe to call repeatedly.
func (s *ProcessSupervisor) Close() error {
	if s == nil {
		return nil
	}
	err := s.Stop(context.Background())
	s.mu.Lock()
	s.state = processSupervisorClosed
	s.mu.Unlock()
	return err
}

func startError(cause error) error {
	if errors.Is(cause, context.Canceled) {
		return fmt.Errorf("%w: %w", ErrProcessSupervisorStart, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrProcessSupervisorStart, context.DeadlineExceeded)
	}
	return ErrProcessSupervisorStart
}

func healthError(cause error) error {
	if errors.Is(cause, context.Canceled) {
		return fmt.Errorf("%w: %w", ErrProcessSupervisorHealth, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrProcessSupervisorHealth, context.DeadlineExceeded)
	}
	return ErrProcessSupervisorHealth
}

func processStopError(ctx, stopContext context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return fmt.Errorf("%w: %w", ErrProcessSupervisorStop, context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(stopContext.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", ErrProcessSupervisorStop, context.DeadlineExceeded)
	}
	return ErrProcessSupervisorStop
}
