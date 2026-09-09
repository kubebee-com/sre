package plugin

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/kubebee-com/sre/pkg/scanner"
)

var (
	ErrRegistryUnavailable = errors.New("plugin registry is unavailable")
	ErrPluginDuplicate     = errors.New("plugin is already registered")
	ErrPluginNotFound      = errors.New("plugin was not found")
	ErrPluginActive        = errors.New("plugin is active")
	ErrRegistrarRequired   = errors.New("analyzer registrar is required")
	ErrSignatureRequired   = errors.New("plugin signature is required")
	ErrSignatureInvalid    = errors.New("plugin signature is invalid")
)

type AnalyzerRegistrar interface {
	RegisterAnalyzer(scanner.Analyzer) error
	UnregisterAnalyzer(string) error
}

type RegistryOptions struct {
	RequireSignature bool
	VerifySignature  func(Metadata, []byte) bool
}

type Status struct {
	Metadata     Metadata `json:"metadata"`
	State        string   `json:"state"`
	AnalyzerName string   `json:"analyzer_name"`
	Endpoint     string   `json:"endpoint,omitempty"`
}

type entry struct {
	client    *Client
	metadata  Metadata
	status    string
	registrar AnalyzerRegistrar
}

type Registry struct {
	lifecycleMu sync.Mutex
	mu          sync.RWMutex
	entries     map[string]*entry
	options     RegistryOptions
}

const (
	StateInactive = "inactive"
	StateActive   = "active"
)

func NewRegistry(options ...RegistryOptions) *Registry {
	var configured RegistryOptions
	if len(options) > 0 {
		configured = options[0]
	}
	return &Registry{entries: make(map[string]*entry), options: configured}
}

// Register records a plugin but does not execute or attach it to a scanner.
// A signature verifier can bind the metadata to an operator-approved artifact.
func (r *Registry) Register(client *Client, signature []byte) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	if client == nil {
		return ErrMetadataRequired
	}
	metadata := Metadata{Name: client.Info().Name, Resource: client.Info().Resource, Description: client.Info().Description, DocsURL: client.Info().DocsURL, ReadOnly: true}
	return r.register(client, metadata, signature)
}

// RegisterDiscovered performs the remote metadata handshake before recording
// the plugin. Activation remains a separate explicit operation.
func (r *Registry) RegisterDiscovered(ctx context.Context, client *Client, signature []byte) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	if client == nil {
		return ErrMetadataRequired
	}
	metadata, err := client.Discover(ctx)
	if err != nil {
		return err
	}
	return r.register(client, metadata, signature)
}

func (r *Registry) register(client *Client, metadata Metadata, signature []byte) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	if client == nil {
		return ErrMetadataRequired
	}
	if r.options.RequireSignature && (r.options.VerifySignature == nil || !r.options.VerifySignature(metadata, signature)) {
		if r.options.VerifySignature == nil {
			return ErrSignatureRequired
		}
		return ErrSignatureInvalid
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	key := strings.ToLower(metadata.Name)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[key]; exists {
		return ErrPluginDuplicate
	}
	r.entries[key] = &entry{client: client, metadata: metadata, status: StateInactive}
	return nil
}

func (r *Registry) Activate(ctx context.Context, name string, registrar AnalyzerRegistrar) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	if registrar == nil {
		return ErrRegistrarRequired
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	r.mu.Lock()
	item, ok := r.entries[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		r.mu.Unlock()
		return ErrPluginNotFound
	}
	if item.status == StateActive {
		r.mu.Unlock()
		return nil
	}
	client := item.client
	r.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := registrar.RegisterAnalyzer(client); err != nil {
		return err
	}
	r.mu.Lock()
	item.status = StateActive
	item.registrar = registrar
	r.mu.Unlock()
	return nil
}

func (r *Registry) Deactivate(name string, registrar AnalyzerRegistrar) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	r.mu.Lock()
	item, ok := r.entries[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		r.mu.Unlock()
		return ErrPluginNotFound
	}
	if item.status != StateActive {
		r.mu.Unlock()
		return nil
	}
	if registrar == nil || item.registrar != registrar {
		r.mu.Unlock()
		return ErrRegistrarRequired
	}
	client := item.client
	item.status = StateInactive
	item.registrar = nil
	r.mu.Unlock()
	if err := registrar.UnregisterAnalyzer(client.Info().Name); err != nil && !errors.Is(err, scanner.ErrAnalyzerNotFound) {
		r.mu.Lock()
		item.status = StateActive
		item.registrar = registrar
		r.mu.Unlock()
		return err
	}
	return nil
}

func (r *Registry) Unregister(name string) error {
	if r == nil {
		return ErrRegistryUnavailable
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	key := strings.ToLower(strings.TrimSpace(name))
	r.mu.Lock()
	item, ok := r.entries[key]
	if !ok {
		r.mu.Unlock()
		return ErrPluginNotFound
	}
	if item.status == StateActive {
		r.mu.Unlock()
		return ErrPluginActive
	}
	delete(r.entries, key)
	r.mu.Unlock()
	return item.client.Close()
}

func (r *Registry) Get(name string) (Status, bool) {
	if r == nil {
		return Status{}, false
	}
	r.mu.RLock()
	item, ok := r.entries[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		r.mu.RUnlock()
		return Status{}, false
	}
	status := Status{Metadata: item.metadata, State: item.status, AnalyzerName: item.client.Info().Name, Endpoint: item.client.endpoint}
	r.mu.RUnlock()
	status.Endpoint = ""
	return status, true
}

func (r *Registry) List() []Status {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	result := make([]Status, 0, len(r.entries))
	for _, item := range r.entries {
		result = append(result, Status{Metadata: item.metadata, State: item.status, AnalyzerName: item.client.Info().Name})
	}
	r.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].Metadata.Name < result[j].Metadata.Name })
	return result
}

func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	r.mu.RLock()
	entries := make([]*entry, 0, len(r.entries))
	keys := make(map[*entry]string, len(r.entries))
	for key, item := range r.entries {
		entries = append(entries, item)
		keys[item] = key
	}
	r.mu.RUnlock()
	var firstErr error
	retained := make(map[string]*entry)
	for _, item := range entries {
		r.mu.RLock()
		active := item.status == StateActive
		registrar := item.registrar
		analyzerName := item.client.Info().Name
		r.mu.RUnlock()
		if active && registrar != nil {
			if err := registrar.UnregisterAnalyzer(analyzerName); err != nil && !errors.Is(err, scanner.ErrAnalyzerNotFound) {
				retained[keys[item]] = item
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			r.mu.Lock()
			item.status = StateInactive
			item.registrar = nil
			r.mu.Unlock()
		}
		if err := item.client.Close(); err != nil && firstErr == nil {
			firstErr = err
			retained[keys[item]] = item
		}
	}
	r.mu.Lock()
	r.entries = retained
	r.mu.Unlock()
	return firstErr
}
