package playbook

import (
	"context"
	"errors"
	"github.com/kubebee-com/sre/pkg/triage"
	"testing"
)

func TestUnavailableServiceObservesCatalog(t *testing.T) {
	s := NewService(NewMemoryCatalog(), nil, ServiceOptions{Settings: DefaultServiceSettings()})
	status, err := s.Status(context.Background())
	if err != nil || status.Available {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	_, err = s.Import(context.Background(), ImportRequest{Content: "test", MediaType: "text/markdown"}, "alice")
	if !errors.Is(err, ErrServiceUnavailable) {
		t.Fatal(err)
	}
}
func TestSettingsCannotRelaxHardFloorsOrAlias(t *testing.T) {
	s := NewService(NewMemoryCatalog(), nil, ServiceOptions{Settings: DefaultServiceSettings()})
	x := s.Settings()
	x.MinConfidence = .1
	if s.UpdateSettings(x, "alice") == nil {
		t.Fatal("relaxed confidence")
	}
	x = s.Settings()
	x.AllowedKinds = []string{"Pod"}
	if err := s.UpdateSettings(x, "alice"); err != nil {
		t.Fatal(err)
	}
	x.AllowedKinds[0] = "Node"
	if s.Settings().AllowedKinds[0] != "Pod" {
		t.Fatal("alias")
	}
}

func TestSettingsCannotWidenConfiguredPolicy(t *testing.T) {
	v := DefaultServiceSettings()
	v.MinConfidence = .95
	v.AllowedNamespaces = []string{"prod"}
	v.AllowedActions = []string{"RestartPod"}
	v.MaxSteps = 2
	s := NewService(NewMemoryCatalog(), nil, ServiceOptions{Settings: v})
	for _, change := range []func(*ServiceSettings){func(x *ServiceSettings) { x.MinConfidence = .8 }, func(x *ServiceSettings) { x.AllowedNamespaces = nil }, func(x *ServiceSettings) { x.AllowedActions = []string{"DeleteFailedPod"} }, func(x *ServiceSettings) { x.MaxSteps = 3 }} {
		x := s.Settings()
		change(&x)
		if s.UpdateSettings(x, "alice") == nil {
			t.Fatal("configured policy widened")
		}
	}
}

type unavailableCatalog struct{ Catalog }

func (unavailableCatalog) Stats(context.Context) (CatalogStats, error) {
	return CatalogStats{}, ErrCatalogUnavailable
}
func TestStatusReportsCatalogUnavailable(t *testing.T) {
	s := NewService(unavailableCatalog{NewMemoryCatalog()}, digestRunner(digestFixture()), ServiceOptions{Settings: DefaultServiceSettings()})
	status, err := s.Status(context.Background())
	if err == nil || status.Available {
		t.Fatalf("%+v %v", status, err)
	}
}

func TestServiceAcceptsConfiguredDefaultConfidence(t *testing.T) {
	v := DefaultServiceSettings()
	v.MinConfidence = .7
	s := NewService(NewMemoryCatalog(), digestRunner(digestFixture()), ServiceOptions{Settings: v})
	if !s.Settings().Enabled || s.Settings().MinConfidence != .7 {
		t.Fatal("valid configured confidence disabled service")
	}
}

type serviceObservation struct {
	tasks    []string
	outcomes []string
	usage    [3]int64
}

func (o *serviceObservation) ObservePlaybookTask(op, provider string, input, output, total int64, err error) {
	o.tasks = append(o.tasks, op)
	o.usage = [3]int64{input, output, total}
}
func (o *serviceObservation) ObservePlaybookOutcome(op, outcome string) {
	o.outcomes = append(o.outcomes, op+":"+outcome)
}
func TestServiceObserverReportsUsageAndLifecycle(t *testing.T) {
	observer := &serviceObservation{}
	runner := serviceRunner(func(ctx context.Context, task triage.StructuredTask) (triage.StructuredTaskResult, error) {
		out, err := digestRunner(digestFixture())(ctx, task)
		out.Usage = triage.ProviderTokenUsage{InputTokens: 11, OutputTokens: 12, TotalTokens: 23}
		return out, err
	})
	s := NewService(NewMemoryCatalog(), runner, ServiceOptions{Settings: DefaultServiceSettings(), Observer: observer})
	out, err := s.Import(context.Background(), ImportRequest{Content: "source", MediaType: "text/markdown"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Transition(context.Background(), out.Playbook.ID, 1, LifecycleActive, "alice"); err != nil {
		t.Fatal(err)
	}
	if err = s.Transition(context.Background(), out.Playbook.ID, 1, LifecycleRetired, "alice"); err != nil {
		t.Fatal(err)
	}
	if observer.usage != [3]int64{11, 12, 23} || !contains(observer.outcomes, "transition:approved") || !contains(observer.outcomes, "transition:retired") {
		t.Fatalf("%+v", observer)
	}
	status, _ := s.Status(context.Background())
	if status.Tasks["digest"].TotalTokens != 23 {
		t.Fatal(status)
	}
}
func TestUnsupportedProviderMarksServiceUnavailable(t *testing.T) {
	s := NewService(NewMemoryCatalog(), serviceRunner(func(context.Context, triage.StructuredTask) (triage.StructuredTaskResult, error) {
		return triage.StructuredTaskResult{}, triage.ErrStructuredTaskUnsupported
	}), ServiceOptions{Settings: DefaultServiceSettings()})
	_, err := s.Import(context.Background(), ImportRequest{Content: "source", MediaType: "text/markdown"}, "alice")
	if !errors.Is(err, ErrServiceUnavailable) {
		t.Fatal(err)
	}
	status, _ := s.Status(context.Background())
	if status.Available {
		t.Fatal(status)
	}
}

func TestServiceAcceptsExplicitConfigBounds(t *testing.T) {
	v := DefaultServiceSettings()
	v.MinConfidence = .1
	v.MaxSteps = 32
	v.MaxSourceBytes = 1 << 20
	v.MaxTotalTextBytes = 4 << 20
	s := NewService(NewMemoryCatalog(), digestRunner(digestFixture()), ServiceOptions{Settings: v})
	if !s.Settings().Enabled || s.Settings().MinConfidence != .1 || s.Settings().MaxSteps != 32 {
		t.Fatal("silently disabled valid explicit configuration")
	}
}

func TestKnownUnsupportedProviderUnavailableBeforeImport(t *testing.T) {
	for _, runner := range []triage.StructuredTaskRunner{triage.NewNoOpProvider(), triage.NewRuleBasedProvider()} {
		s := NewService(NewMemoryCatalog(), runner, ServiceOptions{Settings: DefaultServiceSettings()})
		status, err := s.Status(context.Background())
		if err != nil || status.Available {
			t.Fatalf("unsupported provider appeared available: %+v %v", status, err)
		}
	}
}
