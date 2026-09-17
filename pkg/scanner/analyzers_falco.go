package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/kubebee-com/sre/pkg/sanitizer"
	"k8s.io/client-go/kubernetes"
)

// FalcoSecurityAnalyzer detects runtime security intrusions and policy violations
// reported by Falco either via Kubernetes Events or Falcosidekick telemetry.
type FalcoSecurityAnalyzer struct {
	client kubernetes.Interface
}

func NewFalcoSecurityAnalyzer(client kubernetes.Interface) *FalcoSecurityAnalyzer {
	return &FalcoSecurityAnalyzer{client: client}
}

func (s *ClusterScanner) scanFalcoEvents(ctx context.Context, namespace string) ([]*Issue, error) {
	if s == nil || s.client == nil {
		return nil, ErrKubernetesClientUnavailable
	}
	return NewFalcoSecurityAnalyzer(s.client).Analyze(ctx, namespace)
}

func (a *FalcoSecurityAnalyzer) Info() AnalyzerInfo {
	return AnalyzerInfo{
		Name:        "FalcoSecurityAnalyzer",
		Resource:    "SecurityEvent",
		Description: "Detects runtime security intrusions and behavioral violations reported by Falco",
		Enabled:     true,
	}
}

func (a *FalcoSecurityAnalyzer) Analyze(ctx context.Context, namespace string) ([]*Issue, error) {
	if a == nil || a.client == nil {
		return nil, ErrKubernetesClientUnavailable
	}

	options := listOptionsForScan(ctx)
	events, err := a.client.CoreV1().Events(namespace).List(ctx, options)
	if err != nil {
		return nil, err
	}

	var issues []*Issue
	seen := make(map[string]bool)

	for index := range events.Items {
		event := &events.Items[index]
		isFalco := strings.EqualFold(event.Source.Component, "falco") ||
			strings.Contains(strings.ToLower(event.Reason), "falco") ||
			strings.Contains(strings.ToLower(event.Message), "falco")

		if !isFalco {
			continue
		}

		kind := strings.TrimSpace(event.InvolvedObject.Kind)
		if kind == "" {
			kind = "Pod"
		}
		name := strings.TrimSpace(event.InvolvedObject.Name)
		if name == "" {
			name = event.Name
		}
		ns := event.Namespace
		if ns == "" {
			ns = "default"
		}

		id := generateIssueID(ns, kind, name, string(CategoryFalcoSecurityAlert)+"-"+event.Reason)
		if seen[id] {
			continue
		}
		seen[id] = true

		sanitizedMsg := sanitizer.SanitizeText(event.Message)
		sev := SeverityHigh
		msgLower := strings.ToLower(sanitizedMsg)
		if strings.Contains(msgLower, "critical") || strings.Contains(msgLower, "emergency") || strings.Contains(msgLower, "alert") {
			sev = SeverityCritical
		} else if strings.Contains(msgLower, "notice") || strings.Contains(msgLower, "info") {
			sev = SeverityMedium
		}

		observed := warningEventTime(event)
		issues = append(issues, &Issue{
			ID:                    id,
			Namespace:             ns,
			Kind:                  kind,
			Name:                  name,
			TargetUID:             string(event.InvolvedObject.UID),
			TargetResourceVersion: event.ResourceVersion,
			Severity:              sev,
			Category:              CategoryFalcoSecurityAlert,
			Summary:               fmt.Sprintf("Falco runtime security alert: %s on %s %s", event.Reason, kind, name),
			Details:               sanitizedMsg,
			Events:                []string{sanitizedMsg},
			FirstObserved:         observed,
			LastObserved:          observed,
		})
	}

	return issues, nil
}
