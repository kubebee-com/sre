// Package scanplan defines the validated scope and execution policy for one
// cluster scan. It intentionally has no dependency on scanner so it can be
// shared by the CLI, HTTP API, and background loop.
package scanplan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	SchemaVersion      = "scan/v1"
	DefaultConcurrency = 4
	MaxConcurrency     = 32
	DefaultScanTimeout = 90 * time.Second
	MaxScanTimeout     = 15 * time.Minute
)

type Plan struct {
	SchemaVersion     string        `json:"schema_version"`
	IncludeNamespaces []string      `json:"include_namespaces,omitempty"`
	ExcludeNamespaces []string      `json:"exclude_namespaces,omitempty"`
	LabelSelector     string        `json:"label_selector,omitempty"`
	Kinds             []string      `json:"kinds,omitempty"`
	Names             []string      `json:"names,omitempty"`
	Analyzers         []string      `json:"analyzers,omitempty"`
	MaxConcurrency    int           `json:"max_concurrency,omitempty"`
	Timeout           time.Duration `json:"timeout,omitempty"`
}

type EffectiveScope struct {
	SchemaVersion     string   `json:"schema_version"`
	IncludeNamespaces []string `json:"include_namespaces,omitempty"`
	ExcludeNamespaces []string `json:"exclude_namespaces,omitempty"`
	LabelSelector     string   `json:"label_selector,omitempty"`
	Kinds             []string `json:"kinds,omitempty"`
	Names             []string `json:"names,omitempty"`
	Analyzers         []string `json:"analyzers,omitempty"`
	MaxConcurrency    int      `json:"max_concurrency"`
	Timeout           string   `json:"timeout"`
}

type contextKey struct{}

func Default() Plan {
	return Plan{SchemaVersion: SchemaVersion, MaxConcurrency: DefaultConcurrency, Timeout: DefaultScanTimeout}
}

func (p Plan) normalized() Plan {
	if p.SchemaVersion == "" {
		p.SchemaVersion = SchemaVersion
	}
	p.IncludeNamespaces = normalizeValues(p.IncludeNamespaces)
	p.ExcludeNamespaces = normalizeValues(p.ExcludeNamespaces)
	p.Kinds = normalizeValues(p.Kinds)
	p.Names = normalizeValues(p.Names)
	p.Analyzers = normalizeValues(p.Analyzers)
	p.LabelSelector = strings.TrimSpace(p.LabelSelector)
	if p.MaxConcurrency == 0 {
		p.MaxConcurrency = DefaultConcurrency
	}
	if p.Timeout == 0 {
		p.Timeout = DefaultScanTimeout
	}
	return p
}

func (p Plan) Validate(knownAnalyzers []string) error {
	p = p.normalized()
	if p.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported scan plan schema %q", p.SchemaVersion)
	}
	if _, err := labels.Parse(p.LabelSelector); err != nil {
		return fmt.Errorf("invalid label selector: %w", err)
	}
	if p.MaxConcurrency < 1 || p.MaxConcurrency > MaxConcurrency {
		return fmt.Errorf("max concurrency must be between 1 and %d", MaxConcurrency)
	}
	if p.Timeout < time.Millisecond || p.Timeout > MaxScanTimeout {
		return fmt.Errorf("scan timeout must be between 1ms and %s", MaxScanTimeout)
	}
	if overlap := intersect(p.IncludeNamespaces, p.ExcludeNamespaces); len(overlap) > 0 {
		return fmt.Errorf("namespace is both included and excluded: %s", overlap[0])
	}
	for _, namespace := range append(append([]string(nil), p.IncludeNamespaces...), p.ExcludeNamespaces...) {
		if validationErrors := validation.IsDNS1123Label(namespace); len(validationErrors) > 0 {
			return fmt.Errorf("invalid namespace %q", namespace)
		}
	}
	for _, name := range p.Names {
		if validationErrors := validation.IsDNS1123Subdomain(name); len(validationErrors) > 0 {
			return fmt.Errorf("invalid resource name %q", name)
		}
	}
	for _, kind := range p.Kinds {
		if strings.ContainsAny(kind, "\r\n\x00") {
			return fmt.Errorf("invalid resource kind")
		}
	}
	known := make(map[string]struct{}, len(knownAnalyzers))
	for _, analyzer := range knownAnalyzers {
		known[strings.ToLower(strings.TrimSpace(analyzer))] = struct{}{}
	}
	for _, analyzer := range p.Analyzers {
		if _, ok := known[strings.ToLower(analyzer)]; !ok {
			return fmt.Errorf("unknown analyzer %q", analyzer)
		}
	}
	return nil
}

func (p Plan) EffectiveScope() EffectiveScope {
	p = p.normalized()
	return EffectiveScope{
		SchemaVersion:     p.SchemaVersion,
		IncludeNamespaces: append([]string(nil), p.IncludeNamespaces...),
		ExcludeNamespaces: append([]string(nil), p.ExcludeNamespaces...),
		LabelSelector:     p.LabelSelector,
		Kinds:             append([]string(nil), p.Kinds...),
		Names:             append([]string(nil), p.Names...),
		Analyzers:         append([]string(nil), p.Analyzers...),
		MaxConcurrency:    p.MaxConcurrency,
		Timeout:           p.Timeout.String(),
	}
}

func (p Plan) ListOptions() metav1.ListOptions {
	p = p.normalized()
	options := metav1.ListOptions{LabelSelector: p.LabelSelector}
	if len(p.Names) == 1 {
		options.FieldSelector = fields.OneTermEqualSelector("metadata.name", p.Names[0]).String()
	}
	return options
}

func (p Plan) IncludesNamespace(namespace string) bool {
	p = p.normalized()
	namespace = strings.TrimSpace(namespace)
	if containsFold(p.ExcludeNamespaces, namespace) {
		return false
	}
	return len(p.IncludeNamespaces) == 0 || containsFold(p.IncludeNamespaces, namespace)
}

func (p Plan) Includes(kind, name, namespace string) bool {
	p = p.normalized()
	if !p.IncludesNamespace(namespace) {
		return false
	}
	if len(p.Kinds) > 0 && !containsFold(p.Kinds, kind) {
		return false
	}
	return len(p.Names) == 0 || containsFold(p.Names, name)
}

func (p Plan) IncludesAnalyzer(name string) bool {
	p = p.normalized()
	return len(p.Analyzers) == 0 || containsFold(p.Analyzers, name)
}

func (p Plan) NamespaceArgument() string {
	p = p.normalized()
	if len(p.IncludeNamespaces) == 1 && len(p.ExcludeNamespaces) == 0 {
		return p.IncludeNamespaces[0]
	}
	return ""
}

func WithContext(ctx context.Context, plan Plan) context.Context {
	return context.WithValue(ctx, contextKey{}, plan.normalized())
}

func FromContext(ctx context.Context) (Plan, bool) {
	if ctx == nil {
		return Plan{}, false
	}
	plan, ok := ctx.Value(contextKey{}).(Plan)
	return plan, ok
}

func normalizeValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func intersect(left, right []string) []string {
	var result []string
	for _, value := range left {
		if containsFold(right, value) {
			result = append(result, value)
		}
	}
	return result
}
