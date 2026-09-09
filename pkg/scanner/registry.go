package scanner

import (
	"errors"
	"sort"
	"strings"
	"sync"
)

var (
	ErrAnalyzerNil       = errors.New("analyzer is required")
	ErrAnalyzerInvalid   = errors.New("analyzer metadata is invalid")
	ErrAnalyzerDuplicate = errors.New("analyzer is already registered")
	ErrAnalyzerNotFound  = errors.New("analyzer was not found")
)

// AnalyzerRegistry stores explicitly registered in-process analyzers. It is
// safe to update between scans; each scan receives an immutable snapshot.
type AnalyzerRegistry struct {
	mu        sync.RWMutex
	analyzers map[string]Analyzer
}

func NewAnalyzerRegistry() *AnalyzerRegistry {
	return &AnalyzerRegistry{analyzers: make(map[string]Analyzer)}
}

func (r *AnalyzerRegistry) Register(analyzer Analyzer) error {
	if analyzer == nil {
		return ErrAnalyzerNil
	}
	info := analyzer.Info()
	if !validAnalyzerInfo(info) {
		return ErrAnalyzerInvalid
	}
	key := strings.ToLower(strings.TrimSpace(info.Name))
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.analyzers == nil {
		r.analyzers = make(map[string]Analyzer)
	}
	if _, exists := r.analyzers[key]; exists {
		return ErrAnalyzerDuplicate
	}
	r.analyzers[key] = analyzer
	return nil
}

func (r *AnalyzerRegistry) Unregister(name string) error {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return ErrAnalyzerNotFound
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.analyzers[key]; !exists {
		return ErrAnalyzerNotFound
	}
	delete(r.analyzers, key)
	return nil
}

func (r *AnalyzerRegistry) Get(name string) (Analyzer, bool) {
	if r == nil {
		return nil, false
	}
	key := strings.ToLower(strings.TrimSpace(name))
	r.mu.RLock()
	analyzer, ok := r.analyzers[key]
	r.mu.RUnlock()
	return analyzer, ok
}

func (r *AnalyzerRegistry) List() []Analyzer {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	result := make([]Analyzer, 0, len(r.analyzers))
	for _, analyzer := range r.analyzers {
		result = append(result, analyzer)
	}
	r.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Info().Name) < strings.ToLower(result[j].Info().Name)
	})
	return result
}

func validAnalyzerInfo(info AnalyzerInfo) bool {
	name := strings.TrimSpace(info.Name)
	resource := strings.TrimSpace(info.Resource)
	description := strings.TrimSpace(info.Description)
	if name == "" || len(name) > 128 || resource == "" || len(resource) > 128 || description == "" || len(description) > 4096 {
		return false
	}
	for _, value := range []string{name, resource, description, info.DocsURL} {
		if strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
	}
	return true
}
