// Package integration provides explicit lifecycle management for optional
// analyzer integrations.
package integration

import (
	"context"
	"errors"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/kubebee-com/sre/pkg/scanner"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	maxAnalyzersPerIntegration = 64
	maxRequiredResources       = 64
)

var (
	ErrRegistryUnavailable  = errors.New("integration registry is unavailable")
	ErrIntegrationRequired  = errors.New("integration factory is required")
	ErrMetadataInvalid      = errors.New("integration metadata is invalid")
	ErrIntegrationDuplicate = errors.New("integration is already registered")
	ErrIntegrationNotFound  = errors.New("integration was not found")
	ErrIntegrationActive    = errors.New("integration is active")
	ErrRegistrarRequired    = errors.New("analyzer registrar is required")
	ErrRegistrarMismatch    = errors.New("analyzer registrar does not own this integration")
	ErrActivationFailed     = errors.New("integration activation failed")
	ErrDeactivationFailed   = errors.New("integration deactivation failed")
	ErrNoAnalyzers          = errors.New("integration returned no analyzers")
	ErrAnalyzerInvalid      = errors.New("integration analyzer is invalid")
	ErrFactoryInvalid       = errors.New("integration factory is invalid")
	ErrAnalyzerFailed       = errors.New("integration analyzer failed")

	errFactoryPanic   = errors.New("integration factory failed")
	errRegistrarPanic = errors.New("analyzer registrar failed")
)

// Stable aliases make the lifecycle errors easy to discover without
// duplicating error values or exposing implementation failures.
var (
	ErrFactoryRequired = ErrIntegrationRequired
	ErrDuplicate       = ErrIntegrationDuplicate
	ErrNotFound        = ErrIntegrationNotFound
	ErrAlreadyActive   = ErrIntegrationActive
)

// IntegrationName is an alias for the string identifier used by registry
// callers. Names are canonicalized to lower case when registered.
type IntegrationName = string

// Metadata describes an integration without exposing credentials or runtime
// implementation state.
type Metadata struct {
	Name              string                        `json:"name"`
	DisplayName       string                        `json:"display_name,omitempty"`
	Version           string                        `json:"version,omitempty"`
	Description       string                        `json:"description"`
	DocsURL           string                        `json:"docs_url,omitempty"`
	Owner             string                        `json:"owner,omitempty"`
	Namespace         string                        `json:"namespace,omitempty"`
	ReadOnly          bool                          `json:"read_only"`
	RequiredResources []schema.GroupVersionResource `json:"required_resources,omitempty"`
}

// Factory supplies metadata for one optional integration. A registered
// factory must also implement IntegrationFactory or SingleAnalyzerFactory.
// Keeping this base interface small lets both one-analyzer and analyzer-set
// integrations use the same lifecycle registry.
type Factory interface {
	Metadata() Metadata
}

// IntegrationFactory supplies zero or more analyzers for one integration.
// NewAnalyzers is called only by an explicit Activate call.
type IntegrationFactory interface {
	Factory
	NewAnalyzers(context.Context) ([]scanner.Analyzer, error)
}

// SingleAnalyzerFactory is a convenience contract for integrations with one
// analyzer. It is adapted to the same scanner registrar lifecycle.
type SingleAnalyzerFactory interface {
	Factory
	New(context.Context) (scanner.Analyzer, error)
}

// AnalyzerRegistrar is implemented by scanner.ClusterScanner. The adapter
// returned by NewAnalyzerRegistryRegistrar makes scanner.AnalyzerRegistry
// usable as the same lifecycle target.
type AnalyzerRegistrar interface {
	RegisterAnalyzer(scanner.Analyzer) error
	UnregisterAnalyzer(string) error
}

var _ AnalyzerRegistrar = (*scanner.ClusterScanner)(nil)

// State is the lifecycle state of a registered integration.
type State string

const (
	StateInactive State = "inactive"
	StateActive   State = "active"
)

// Status is a point-in-time snapshot safe to return to callers. AnalyzerNames
// is populated only after a successful activation.
type Status struct {
	Metadata
	State         State    `json:"state"`
	AnalyzerNames []string `json:"analyzer_names,omitempty"`
}

// Registration is an alias for Status for callers that prefer registration
// terminology.
type Registration = Status

type registeredIntegration struct {
	factory  Factory
	metadata Metadata
	mu       sync.Mutex
	active   *activation
}

type activation struct {
	registrar     AnalyzerRegistrar
	analyzers     []*managedAnalyzer
	analyzerNames []string
}

// Registry holds registered integration factories and their activation state.
// Registration is not activation: a factory cannot run until Activate is
// called explicitly.
type Registry struct {
	mu          sync.RWMutex
	lifecycleMu sync.Mutex
	entries     map[string]*registeredIntegration
}

// NewRegistry returns an empty, inactive integration registry.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]*registeredIntegration)}
}

// Register validates and stores an integration factory without running it or
// modifying any scanner registrar.
func (r *Registry) Register(factory Factory) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	if isNil(factory) {
		return ErrIntegrationRequired
	}
	if !supportsAnalyzerFactory(factory) {
		return ErrFactoryInvalid
	}

	metadata, ok := readMetadata(factory)
	if !ok {
		return ErrMetadataInvalid
	}
	metadata, ok = normalizeMetadata(metadata)
	if !ok {
		return ErrMetadataInvalid
	}
	key := integrationKey(metadata.Name)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]*registeredIntegration)
	}
	if _, exists := r.entries[key]; exists {
		return ErrIntegrationDuplicate
	}
	r.entries[key] = &registeredIntegration{
		factory:  factory,
		metadata: cloneMetadata(metadata),
	}
	return nil
}

// Unregister removes an inactive definition. An active integration must first
// be deactivated against its registrar so the registry cannot orphan a
// scanner analyzer.
func (r *Registry) Unregister(name string) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	key := integrationKey(name)
	if key == "" {
		return ErrIntegrationNotFound
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	r.mu.Lock()
	entry, ok := r.entries[key]
	if !ok {
		r.mu.Unlock()
		return ErrIntegrationNotFound
	}
	entry.mu.Lock()
	if entry.active != nil {
		entry.mu.Unlock()
		r.mu.Unlock()
		return ErrIntegrationActive
	}
	delete(r.entries, key)
	entry.mu.Unlock()
	r.mu.Unlock()
	return nil
}

// Get returns a point-in-time status snapshot for name.
func (r *Registry) Get(name string) (Status, bool) {
	if r == nil {
		return Status{}, false
	}
	entry, ok := r.find(name)
	if !ok {
		return Status{}, false
	}
	return entry.status(), true
}

// List returns all registered integrations in stable name order.
func (r *Registry) List() []Status {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	entries := make([]*registeredIntegration, 0, len(r.entries))
	for _, entry := range r.entries {
		entries = append(entries, entry)
	}
	r.mu.RUnlock()

	statuses := make([]Status, 0, len(entries))
	for _, entry := range entries {
		statuses = append(statuses, entry.status())
	}
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Name < statuses[j].Name
	})
	return statuses
}

// IsActive reports whether name is currently active.
func (r *Registry) IsActive(name string) bool {
	status, ok := r.Get(name)
	return ok && status.State == StateActive
}

// Active is an alias for IsActive.
func (r *Registry) Active(name string) bool {
	return r.IsActive(name)
}

// Activate explicitly creates and registers an integration's analyzers. All
// analyzer metadata is validated before the first registrar mutation. A
// partial registrar update is rolled back if a later registration fails.
func (r *Registry) Activate(ctx context.Context, name string, registrar AnalyzerRegistrar) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	entry, ok := r.find(name)
	if !ok {
		return ErrIntegrationNotFound
	}

	// Serialize lifecycle changes across integrations. The external registrar
	// may be a shared scanner registry and rollback must not interleave with a
	// concurrent activation or deactivation.
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.active != nil {
		if isNil(registrar) {
			return ErrRegistrarRequired
		}
		if sameRegistrar(entry.active.registrar, registrar) {
			return nil
		}
		return ErrRegistrarMismatch
	}
	if isNil(registrar) {
		return ErrRegistrarRequired
	}
	if ctx == nil {
		return ErrActivationFailed
	}
	if err := ctx.Err(); err != nil {
		return safeLifecycleError(ErrActivationFailed, err)
	}

	rawAnalyzers, err := newAnalyzers(entry.factory, ctx)
	if err != nil {
		return safeLifecycleError(ErrActivationFailed, err)
	}
	managed, names, err := validateAnalyzers(rawAnalyzers)
	if err != nil {
		return safeLifecycleError(ErrActivationFailed, err)
	}

	registered := make([]string, 0, len(managed))
	for index, analyzer := range managed {
		if err := ctx.Err(); err != nil {
			r.rollback(registrar, registered)
			closeManagedAnalyzers(managed)
			return safeLifecycleError(ErrActivationFailed, err)
		}
		if err := registerAnalyzer(registrar, analyzer); err != nil {
			r.rollback(registrar, registered)
			closeManagedAnalyzers(managed)
			return safeLifecycleError(ErrActivationFailed, err)
		}
		registered = append(registered, names[index])
	}
	for _, analyzer := range managed {
		analyzer.setActive(true)
	}

	entry.active = &activation{
		registrar:     registrar,
		analyzers:     append([]*managedAnalyzer(nil), managed...),
		analyzerNames: append([]string(nil), names...),
	}
	return nil
}

// Deactivate explicitly unregisters the analyzers previously owned by name.
// Repeated deactivation is a no-op. If an external registrar fails to remove
// one or more analyzers, the integration remains active and can be retried.
func (r *Registry) Deactivate(name string, registrar AnalyzerRegistrar) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	entry, ok := r.find(name)
	if !ok {
		return ErrIntegrationNotFound
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.active == nil {
		return nil
	}
	if isNil(registrar) {
		return ErrRegistrarRequired
	}
	if !sameRegistrar(entry.active.registrar, registrar) {
		return ErrRegistrarMismatch
	}

	active := entry.active
	remainingAnalyzers := make([]*managedAnalyzer, 0, len(active.analyzers))
	remainingNames := make([]string, 0, len(active.analyzerNames))
	var firstErr error
	for index, name := range active.analyzerNames {
		var analyzer *managedAnalyzer
		if index < len(active.analyzers) {
			analyzer = active.analyzers[index]
			analyzer.setActive(false)
		}
		err := unregisterAnalyzer(registrar, name)
		if err == nil || errors.Is(err, scanner.ErrAnalyzerNotFound) {
			if analyzer != nil {
				if closeErr := analyzer.close(); closeErr != nil && firstErr == nil {
					firstErr = closeErr
				}
			}
			continue
		}
		if analyzer != nil {
			analyzer.setActive(true)
			remainingAnalyzers = append(remainingAnalyzers, analyzer)
		}
		remainingNames = append(remainingNames, name)
		if firstErr == nil {
			firstErr = err
		}
	}

	if len(remainingNames) == 0 {
		entry.active = nil
		if firstErr != nil {
			return safeLifecycleError(ErrDeactivationFailed, firstErr)
		}
		return nil
	}
	entry.active = &activation{
		registrar:     active.registrar,
		analyzers:     remainingAnalyzers,
		analyzerNames: remainingNames,
	}
	return safeLifecycleError(ErrDeactivationFailed, firstErr)
}

// Close deactivates all active integrations, unregisters their owned
// analyzers, closes optional analyzer resources, and then drops definitions.
func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	r.mu.RLock()
	entries := make([]*registeredIntegration, 0, len(r.entries))
	for _, entry := range r.entries {
		entries = append(entries, entry)
	}
	r.mu.RUnlock()

	var firstErr error
	keepEntries := make([]*registeredIntegration, 0)
	for _, entry := range entries {
		entry.mu.Lock()
		active := entry.active
		if active == nil {
			entry.mu.Unlock()
			continue
		}
		remainingAnalyzers := make([]*managedAnalyzer, 0, len(active.analyzers))
		remainingNames := make([]string, 0, len(active.analyzerNames))
		for index, name := range active.analyzerNames {
			var analyzer *managedAnalyzer
			if index < len(active.analyzers) {
				analyzer = active.analyzers[index]
				analyzer.setActive(false)
			}
			if err := unregisterAnalyzer(active.registrar, name); err != nil && !errors.Is(err, scanner.ErrAnalyzerNotFound) {
				if analyzer != nil {
					analyzer.setActive(true)
					remainingAnalyzers = append(remainingAnalyzers, analyzer)
				}
				remainingNames = append(remainingNames, name)
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if analyzer != nil {
				if err := analyzer.close(); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
		for index := len(active.analyzerNames); index < len(active.analyzers); index++ {
			active.analyzers[index].setActive(true)
			remainingAnalyzers = append(remainingAnalyzers, active.analyzers[index])
		}
		if len(remainingNames) > 0 {
			entry.active = &activation{registrar: active.registrar, analyzers: remainingAnalyzers, analyzerNames: remainingNames}
			keepEntries = append(keepEntries, entry)
		} else {
			entry.active = nil
		}
		entry.mu.Unlock()
	}
	r.mu.Lock()
	if len(keepEntries) == 0 {
		r.entries = make(map[string]*registeredIntegration)
	} else {
		retained := make(map[string]*registeredIntegration, len(keepEntries))
		for _, entry := range keepEntries {
			retained[integrationKey(entry.metadata.Name)] = entry
		}
		r.entries = retained
	}
	r.mu.Unlock()
	if firstErr != nil {
		return safeLifecycleError(ErrDeactivationFailed, firstErr)
	}
	return nil
}

// AnalyzerRegistryRegistrar adapts scanner.AnalyzerRegistry to AnalyzerRegistrar
// without duplicating scanner registry behavior.
type AnalyzerRegistryRegistrar struct {
	registry *scanner.AnalyzerRegistry
}

// NewAnalyzerRegistryRegistrar returns an adapter for registry.
func NewAnalyzerRegistryRegistrar(registry *scanner.AnalyzerRegistry) *AnalyzerRegistryRegistrar {
	return &AnalyzerRegistryRegistrar{registry: registry}
}

func (r *AnalyzerRegistryRegistrar) RegisterAnalyzer(analyzer scanner.Analyzer) error {
	if r == nil || r.registry == nil {
		return ErrRegistrarRequired
	}
	return r.registry.Register(analyzer)
}

func (r *AnalyzerRegistryRegistrar) UnregisterAnalyzer(name string) error {
	if r == nil || r.registry == nil {
		return ErrRegistrarRequired
	}
	return r.registry.Unregister(name)
}

type managedAnalyzer struct {
	info     scanner.AnalyzerInfo
	delegate scanner.Analyzer
	mu       sync.RWMutex
	active   bool
}

func (a *managedAnalyzer) Info() scanner.AnalyzerInfo {
	return a.info
}

func (a *managedAnalyzer) Analyze(ctx context.Context, namespace string) (issues []*scanner.Issue, err error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.active {
		return nil, nil
	}
	defer func() {
		if recover() != nil {
			issues = nil
			err = ErrAnalyzerFailed
		}
	}()
	return a.delegate.Analyze(ctx, namespace)
}

func (a *managedAnalyzer) setActive(active bool) {
	a.mu.Lock()
	a.active = active
	a.mu.Unlock()
}

func (a *managedAnalyzer) close() error {
	if a == nil || a.delegate == nil {
		return nil
	}
	if closer, ok := a.delegate.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func (r *Registry) find(name string) (*registeredIntegration, bool) {
	key := integrationKey(name)
	if key == "" {
		return nil, false
	}
	r.mu.RLock()
	entry, ok := r.entries[key]
	r.mu.RUnlock()
	return entry, ok
}

func (e *registeredIntegration) status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	status := Status{
		Metadata: cloneMetadata(e.metadata),
		State:    StateInactive,
	}
	if e.active != nil {
		status.State = StateActive
		status.AnalyzerNames = append([]string(nil), e.active.analyzerNames...)
	}
	return status
}

func (r *Registry) rollback(registrar AnalyzerRegistrar, names []string) {
	for index := len(names) - 1; index >= 0; index-- {
		_ = unregisterAnalyzer(registrar, names[index])
	}
}

func closeManagedAnalyzers(analyzers []*managedAnalyzer) {
	for _, analyzer := range analyzers {
		if analyzer != nil {
			_ = analyzer.close()
		}
	}
}

func supportsAnalyzerFactory(factory Factory) bool {
	_, multiple := factory.(IntegrationFactory)
	_, single := factory.(SingleAnalyzerFactory)
	return multiple || single
}

func readMetadata(factory Factory) (metadata Metadata, ok bool) {
	defer func() {
		if recover() != nil {
			metadata = Metadata{}
			ok = false
		}
	}()
	return factory.Metadata(), true
}

func normalizeMetadata(metadata Metadata) (Metadata, bool) {
	metadata.Name = strings.ToLower(strings.TrimSpace(metadata.Name))
	metadata.DisplayName = strings.TrimSpace(metadata.DisplayName)
	metadata.Version = strings.TrimSpace(metadata.Version)
	metadata.Description = strings.TrimSpace(metadata.Description)
	metadata.DocsURL = strings.TrimSpace(metadata.DocsURL)
	metadata.Owner = strings.TrimSpace(metadata.Owner)
	metadata.Namespace = strings.TrimSpace(metadata.Namespace)
	if !validMetadata(metadata) {
		return Metadata{}, false
	}
	metadata.RequiredResources = append([]schema.GroupVersionResource(nil), metadata.RequiredResources...)
	return metadata, true
}

func validMetadata(metadata Metadata) bool {
	if metadata.Name == "" || len(metadata.Name) > 128 || !validIdentifier(metadata.Name) {
		return false
	}
	if metadata.Description == "" || len(metadata.Description) > 4096 {
		return false
	}
	if len(metadata.DisplayName) > 128 || len(metadata.Version) > 128 || len(metadata.Owner) > 128 || len(metadata.Namespace) > 63 || len(metadata.DocsURL) > 2048 {
		return false
	}
	for _, value := range []string{metadata.Name, metadata.DisplayName, metadata.Version, metadata.Description, metadata.Owner, metadata.Namespace, metadata.DocsURL} {
		if strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
	}
	if metadata.DocsURL != "" {
		parsed, err := url.Parse(metadata.DocsURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return false
		}
	}
	if len(metadata.RequiredResources) > maxRequiredResources {
		return false
	}
	for _, resource := range metadata.RequiredResources {
		if resource.Version == "" || resource.Resource == "" || !safeText(resource.Group, 128) || !safeText(resource.Version, 64) || !safeText(resource.Resource, 128) {
			return false
		}
	}
	return true
}

func validIdentifier(value string) bool {
	for index, character := range value {
		if index == 0 && !isASCIIAlphaNumeric(character) {
			return false
		}
		if !isASCIIAlphaNumeric(character) && character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func isASCIIAlphaNumeric(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func safeText(value string, max int) bool {
	return len(value) <= max && !strings.ContainsAny(value, "\r\n\x00")
}

func integrationKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func newAnalyzers(factory Factory, ctx context.Context) (analyzers []scanner.Analyzer, err error) {
	defer func() {
		if recover() != nil {
			analyzers = nil
			err = errFactoryPanic
		}
	}()
	switch factory := factory.(type) {
	case IntegrationFactory:
		return factory.NewAnalyzers(ctx)
	case SingleAnalyzerFactory:
		analyzer, err := factory.New(ctx)
		if err != nil {
			return nil, err
		}
		if isNil(analyzer) {
			return nil, ErrAnalyzerInvalid
		}
		return []scanner.Analyzer{analyzer}, nil
	default:
		return nil, ErrFactoryInvalid
	}
}

func validateAnalyzers(analyzers []scanner.Analyzer) ([]*managedAnalyzer, []string, error) {
	if len(analyzers) == 0 {
		return nil, nil, ErrNoAnalyzers
	}
	if len(analyzers) > maxAnalyzersPerIntegration {
		return nil, nil, ErrAnalyzerInvalid
	}
	validator := scanner.NewAnalyzerRegistry()
	managed := make([]*managedAnalyzer, 0, len(analyzers))
	names := make([]string, 0, len(analyzers))
	for _, analyzer := range analyzers {
		info, ok := readAnalyzerInfo(analyzer)
		if !ok {
			return nil, nil, ErrAnalyzerInvalid
		}
		info.Name = strings.TrimSpace(info.Name)
		candidate := &managedAnalyzer{info: info, delegate: analyzer}
		if err := validator.Register(candidate); err != nil {
			return nil, nil, ErrAnalyzerInvalid
		}
		managed = append(managed, candidate)
		names = append(names, info.Name)
	}
	return managed, names, nil
}

func readAnalyzerInfo(analyzer scanner.Analyzer) (info scanner.AnalyzerInfo, ok bool) {
	if isNil(analyzer) {
		return scanner.AnalyzerInfo{}, false
	}
	defer func() {
		if recover() != nil {
			info = scanner.AnalyzerInfo{}
			ok = false
		}
	}()
	return analyzer.Info(), true
}

func registerAnalyzer(registrar AnalyzerRegistrar, analyzer scanner.Analyzer) (err error) {
	defer func() {
		if recover() != nil {
			err = errRegistrarPanic
		}
	}()
	return registrar.RegisterAnalyzer(analyzer)
}

func unregisterAnalyzer(registrar AnalyzerRegistrar, name string) (err error) {
	defer func() {
		if recover() != nil {
			err = errRegistrarPanic
		}
	}()
	return registrar.UnregisterAnalyzer(name)
}

func sameRegistrar(left, right AnalyzerRegistrar) bool {
	if isNil(left) || isNil(right) {
		return false
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	if leftValue.Type() != rightValue.Type() {
		return false
	}
	if leftValue.Type().Comparable() {
		return leftValue.Interface() == rightValue.Interface()
	}
	if leftValue.Kind() == reflect.Pointer {
		return leftValue.Pointer() == rightValue.Pointer()
	}
	return false
}

func safeLifecycleError(public, cause error) error {
	if errors.Is(cause, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return public
}

func cloneMetadata(metadata Metadata) Metadata {
	metadata.RequiredResources = append([]schema.GroupVersionResource(nil), metadata.RequiredResources...)
	return metadata
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
