package integration

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kubebee-com/sre/pkg/scanner"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type registryTestFactory struct {
	metadata Metadata
	new      func(context.Context) (scanner.Analyzer, error)
	calls    atomic.Int32
}

func (f *registryTestFactory) Metadata() Metadata {
	return f.metadata
}

func (f *registryTestFactory) New(ctx context.Context) (scanner.Analyzer, error) {
	f.calls.Add(1)
	return f.new(ctx)
}

type registryTestAnalyzerSetFactory struct {
	metadata  Metadata
	analyzers []scanner.Analyzer
	calls     atomic.Int32
}

func (f *registryTestAnalyzerSetFactory) Metadata() Metadata {
	return f.metadata
}

func (f *registryTestAnalyzerSetFactory) NewAnalyzers(context.Context) ([]scanner.Analyzer, error) {
	f.calls.Add(1)
	return append([]scanner.Analyzer(nil), f.analyzers...), nil
}

type registryTestAnalyzer struct {
	info           scanner.AnalyzerInfo
	calls          atomic.Int32
	panicOnAnalyze bool
}

type closableRegistryTestAnalyzer struct {
	registryTestAnalyzer
	closeCalls atomic.Int32
}

func (a *closableRegistryTestAnalyzer) Close() error {
	a.closeCalls.Add(1)
	return nil
}

func (a *registryTestAnalyzer) Info() scanner.AnalyzerInfo {
	return a.info
}

func (a *registryTestAnalyzer) Analyze(context.Context, string) ([]*scanner.Issue, error) {
	a.calls.Add(1)
	if a.panicOnAnalyze {
		panic("integration secret=should-not-escape")
	}
	return nil, nil
}

type registryTestRegistrar struct {
	mu              sync.Mutex
	analyzers       map[string]scanner.Analyzer
	registerCalls   int
	unregisterCalls int
	registerErr     error
	unregisterErr   error
	failRegisterAt  int
}

func newRegistryTestRegistrar() *registryTestRegistrar {
	return &registryTestRegistrar{analyzers: make(map[string]scanner.Analyzer)}
}

func (r *registryTestRegistrar) RegisterAnalyzer(analyzer scanner.Analyzer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registerCalls++
	if r.registerErr != nil {
		return r.registerErr
	}
	if r.failRegisterAt > 0 && r.registerCalls == r.failRegisterAt {
		return errors.New("registrar secret=should-not-escape")
	}
	r.analyzers[analyzer.Info().Name] = analyzer
	return nil
}

func (r *registryTestRegistrar) UnregisterAnalyzer(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unregisterCalls++
	if r.unregisterErr != nil {
		return r.unregisterErr
	}
	if _, ok := r.analyzers[name]; !ok {
		return scanner.ErrAnalyzerNotFound
	}
	delete(r.analyzers, name)
	return nil
}

func (r *registryTestRegistrar) analyzer(name string) scanner.Analyzer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.analyzers[name]
}

func (r *registryTestRegistrar) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registerCalls, r.unregisterCalls
}

func validRegistryTestMetadata(name string) Metadata {
	return Metadata{
		Name:        IntegrationName(name),
		DisplayName: name,
		Description: "test integration",
		Owner:       "sre",
		DocsURL:     "https://example.invalid/integrations/" + name,
	}
}

func validRegistryTestFactory(name string, analyzer *registryTestAnalyzer) *registryTestFactory {
	return &registryTestFactory{
		metadata: validRegistryTestMetadata(name),
		new: func(context.Context) (scanner.Analyzer, error) {
			return analyzer, nil
		},
	}
}

func TestRegistryRegisterValidatesAndSnapshotsMetadata(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(nil); !errors.Is(err, ErrFactoryRequired) {
		t.Fatalf("Register(nil) error = %v, want ErrFactoryRequired", err)
	}
	invalid := validRegistryTestFactory("invalid", &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "invalid-analyzer", Resource: "Pod", Description: "test analyzer",
	}})
	invalid.metadata.Description = ""
	if err := registry.Register(invalid); !errors.Is(err, ErrMetadataInvalid) {
		t.Fatalf("Register(invalid) error = %v, want ErrMetadataInvalid", err)
	}

	first := validRegistryTestFactory("zeta", &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "zeta-analyzer", Resource: "Pod", Description: "test analyzer",
	}})
	second := validRegistryTestFactory("alpha", &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "alpha-analyzer", Resource: "Pod", Description: "test analyzer",
	}})
	first.metadata.RequiredResources = []schema.GroupVersionResource{{Version: "v1", Resource: "pods"}}
	if err := registry.Register(first); err != nil {
		t.Fatalf("Register(first) error = %v", err)
	}
	if err := registry.Register(second); err != nil {
		t.Fatalf("Register(second) error = %v", err)
	}
	if err := registry.Register(first); !errors.Is(err, ErrIntegrationDuplicate) {
		t.Fatalf("duplicate Register() error = %v, want ErrIntegrationDuplicate", err)
	}

	first.metadata.RequiredResources[0].Resource = "mutated"
	got, ok := registry.Get(" ZETA ")
	if !ok {
		t.Fatal("Get() did not find normalized integration name")
	}
	if got.Name != "zeta" || got.RequiredResources[0].Resource != "pods" {
		t.Fatalf("Get() = %#v, want normalized defensive metadata copy", got)
	}
	list := registry.List()
	if len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "zeta" {
		t.Fatalf("List() = %#v, want sorted metadata", list)
	}
	if registry.IsActive("zeta") {
		t.Fatal("new integration is active before Activate")
	}
}

func TestRegistryActivationLifecycleIsExplicitIdempotentAndGated(t *testing.T) {
	registry := NewRegistry()
	analyzer := &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "prometheus-analyzer", Resource: "Pod", Description: "test analyzer",
	}}
	factory := validRegistryTestFactory("Prometheus", analyzer)
	if err := registry.Register(factory); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registrar := newRegistryTestRegistrar()

	if analyzer.calls.Load() != 0 {
		t.Fatal("analyzer ran before activation")
	}
	if err := registry.Activate(context.Background(), "prometheus", registrar); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := registry.Activate(context.Background(), "PROMETHEUS", registrar); err != nil {
		t.Fatalf("idempotent Activate() error = %v", err)
	}
	if factory.calls.Load() != 1 {
		t.Fatalf("factory calls = %d, want one for idempotent activation", factory.calls.Load())
	}
	registerCalls, unregisterCalls := registrar.counts()
	if registerCalls != 1 || unregisterCalls != 0 {
		t.Fatalf("registrar calls = (%d, %d), want (1, 0)", registerCalls, unregisterCalls)
	}
	if !registry.IsActive("prometheus") {
		t.Fatal("integration is inactive after Activate")
	}

	registered := registrar.analyzer("prometheus-analyzer")
	if registered == nil {
		t.Fatal("Activate() did not register analyzer")
	}
	if _, err := registered.Analyze(context.Background(), ""); err != nil {
		t.Fatalf("active analyzer Analyze() error = %v", err)
	}
	if analyzer.calls.Load() != 1 {
		t.Fatalf("analyzer calls = %d, want one while active", analyzer.calls.Load())
	}

	if err := registry.Deactivate("prometheus", registrar); err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if err := registry.Deactivate("prometheus", registrar); err != nil {
		t.Fatalf("idempotent Deactivate() error = %v", err)
	}
	if registry.IsActive("prometheus") {
		t.Fatal("integration is active after Deactivate")
	}
	if _, err := registered.Analyze(context.Background(), ""); err != nil {
		t.Fatalf("inactive analyzer Analyze() error = %v", err)
	}
	if analyzer.calls.Load() != 1 {
		t.Fatalf("inactive analyzer calls = %d, want no additional execution", analyzer.calls.Load())
	}
	registerCalls, unregisterCalls = registrar.counts()
	if registerCalls != 1 || unregisterCalls != 1 {
		t.Fatalf("registrar calls after deactivate = (%d, %d), want (1, 1)", registerCalls, unregisterCalls)
	}

	if err := registry.Activate(context.Background(), "prometheus", registrar); err != nil {
		t.Fatalf("reactivation error = %v", err)
	}
	if factory.calls.Load() != 2 {
		t.Fatalf("factory calls after reactivation = %d, want two", factory.calls.Load())
	}
}

func TestRegistryLifecycleErrorsAreSafeAndTransactional(t *testing.T) {
	registry := NewRegistry()
	factoryErr := errors.New("upstream token=super-secret")
	factory := validRegistryTestFactory("broken", &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "broken-analyzer", Resource: "Pod", Description: "test analyzer",
	}})
	factory.new = func(context.Context) (scanner.Analyzer, error) { return nil, factoryErr }
	if err := registry.Register(factory); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registrar := newRegistryTestRegistrar()
	registrar.registerErr = errors.New("remote password=super-secret")

	err := registry.Activate(context.Background(), "broken", registrar)
	if !errors.Is(err, ErrActivationFailed) || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("Activate() error = %v, want safe ErrActivationFailed", err)
	}
	if registry.IsActive("broken") {
		t.Fatal("failed activation became active")
	}
	if got := registrar.analyzer("broken-analyzer"); got != nil {
		t.Fatal("failed activation left an analyzer registered")
	}

	working := validRegistryTestFactory("working", &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "working-analyzer", Resource: "Pod", Description: "test analyzer",
	}})
	if err := registry.Register(working); err != nil {
		t.Fatalf("Register(working) error = %v", err)
	}
	registrar.registerErr = nil
	if err := registry.Activate(context.Background(), "working", registrar); err != nil {
		t.Fatalf("working Activate() error = %v", err)
	}
	registrar.unregisterErr = errors.New("delete credential=super-secret")
	err = registry.Deactivate("working", registrar)
	if !errors.Is(err, ErrDeactivationFailed) || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("Deactivate() error = %v, want safe ErrDeactivationFailed", err)
	}
	if !registry.IsActive("working") {
		t.Fatal("failed deactivation lost active state")
	}
	registrar.unregisterErr = nil
	if err := registry.Deactivate("working", registrar); err != nil {
		t.Fatalf("retry Deactivate() error = %v", err)
	}
}

func TestRegistryMultiAnalyzerActivationRollsBackPartialRegistration(t *testing.T) {
	registry := NewRegistry()
	first := &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "first-analyzer", Resource: "Pod", Description: "test analyzer",
	}}
	second := &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "second-analyzer", Resource: "Pod", Description: "test analyzer",
	}}
	factory := &registryTestAnalyzerSetFactory{
		metadata:  validRegistryTestMetadata("multi"),
		analyzers: []scanner.Analyzer{first, second},
	}
	if err := registry.Register(factory); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registrar := newRegistryTestRegistrar()
	registrar.failRegisterAt = 2

	err := registry.Activate(context.Background(), "multi", registrar)
	if !errors.Is(err, ErrActivationFailed) || strings.Contains(err.Error(), "should-not-escape") {
		t.Fatalf("Activate() error = %v, want safe rollback error", err)
	}
	if registry.IsActive("multi") {
		t.Fatal("partially activated integration is active")
	}
	if registrar.analyzer("first-analyzer") != nil || registrar.analyzer("second-analyzer") != nil {
		t.Fatal("partial activation left an analyzer registered")
	}
	registerCalls, unregisterCalls := registrar.counts()
	if registerCalls != 2 || unregisterCalls != 1 {
		t.Fatalf("registrar calls = (%d, %d), want (2, 1) after rollback", registerCalls, unregisterCalls)
	}
}

func TestRegistryAdapterAndAnalyzerPanicAreSafe(t *testing.T) {
	registry := NewRegistry()
	analyzer := &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "panic-analyzer", Resource: "Pod", Description: "test analyzer",
	}, panicOnAnalyze: true}
	if err := registry.Register(validRegistryTestFactory("adapter", analyzer)); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	scannerRegistry := scanner.NewAnalyzerRegistry()
	registrar := NewAnalyzerRegistryRegistrar(scannerRegistry)
	if err := registry.Activate(context.Background(), "adapter", registrar); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	registered, ok := scannerRegistry.Get("panic-analyzer")
	if !ok {
		t.Fatal("scanner registry adapter did not register analyzer")
	}
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("managed analyzer panicked: %v", recovered)
			}
		}()
		_, err := registered.Analyze(context.Background(), "")
		if !errors.Is(err, ErrAnalyzerFailed) || strings.Contains(err.Error(), "should-not-escape") {
			t.Fatalf("Analyze() error = %v, want safe ErrAnalyzerFailed", err)
		}
	}()
	if err := registry.Deactivate("adapter", registrar); err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if _, ok := scannerRegistry.Get("panic-analyzer"); ok {
		t.Fatal("adapter left analyzer registered after deactivation")
	}
	if err := registry.Unregister("adapter"); err != nil {
		t.Fatalf("Unregister() error = %v", err)
	}
}

func TestRegistryClosesOwnedAnalyzerResourcesOnDeactivateAndClose(t *testing.T) {
	delegate := &closableRegistryTestAnalyzer{registryTestAnalyzer: registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "owned-analyzer", Resource: "Pod", Description: "owned analyzer",
	}}}
	factory := &registryTestFactory{
		metadata: validRegistryTestMetadata("owned"),
		new:      func(context.Context) (scanner.Analyzer, error) { return delegate, nil },
	}
	registry := NewRegistry()
	if err := registry.Register(factory); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registrar := newRegistryTestRegistrar()
	if err := registry.Activate(context.Background(), "owned", registrar); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := registry.Deactivate("owned", registrar); err != nil {
		t.Fatalf("Deactivate() error = %v", err)
	}
	if delegate.closeCalls.Load() != 1 {
		t.Fatalf("delegate Close() calls = %d, want 1", delegate.closeCalls.Load())
	}

	if err := registry.Activate(context.Background(), "owned", registrar); err != nil {
		t.Fatalf("reactivation error = %v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if delegate.closeCalls.Load() != 2 {
		t.Fatalf("delegate Close() calls after registry Close = %d, want 2", delegate.closeCalls.Load())
	}
}

func TestRegistryLifecycleIsSafeUnderConcurrentCalls(t *testing.T) {
	registry := NewRegistry()
	analyzer := &registryTestAnalyzer{info: scanner.AnalyzerInfo{
		Name: "concurrent-analyzer", Resource: "Pod", Description: "test analyzer",
	}}
	if err := registry.Register(validRegistryTestFactory("concurrent", analyzer)); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	registrar := newRegistryTestRegistrar()

	var group sync.WaitGroup
	for i := 0; i < 64; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			if i%2 == 0 {
				if err := registry.Activate(context.Background(), "concurrent", registrar); err != nil {
					t.Errorf("Activate() error = %v", err)
				}
				return
			}
			if err := registry.Deactivate("concurrent", registrar); err != nil {
				t.Errorf("Deactivate() error = %v", err)
			}
		}(i)
	}
	group.Wait()
}
