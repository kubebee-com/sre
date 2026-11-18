package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

func TestNewAlertmanagerNotifierNormalizesEndpointAndRejectsInvalid(t *testing.T) {
	am, err := NewAlertmanagerNotifier(AlertmanagerOptions{
		Endpoint:  "http://monitoring-alertmanager.monitoring.svc.cluster.local:9093",
		PublicURL: "https://sre.example.com",
	})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	if !am.Enabled() {
		t.Fatal("expected AlertmanagerNotifier to be enabled")
	}
	want := "http://monitoring-alertmanager.monitoring.svc.cluster.local:9093/api/v2/alerts"
	if am.endpoint != want {
		t.Fatalf("endpoint = %q, want %q", am.endpoint, want)
	}

	for _, bad := range []string{
		"ftp://alertmanager.invalid",
		"http://user:pass@alertmanager.invalid:9093",
		"http://alertmanager.invalid:9093\r\nX-Injected: true",
	} {
		if _, err := NewAlertmanagerNotifier(AlertmanagerOptions{Endpoint: bad}); err == nil {
			t.Errorf("expected invalid Alertmanager endpoint %q to fail", bad)
		}
	}
}

func TestAlertmanagerNotifierSyncsFoldedSeriousAlertsFiltersPostureAndResolves(t *testing.T) {
	var (
		mu       sync.Mutex
		requests [][]alertmanagerAlert
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			t.Errorf("unexpected path = %q", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var decoded []alertmanagerAlert
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("decode alert payload: %v", err)
		}
		mu.Lock()
		requests = append(requests, decoded)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	am, err := NewAlertmanagerNotifier(AlertmanagerOptions{
		Endpoint:     ts.URL,
		MinSeverity:  "HIGH",
		PublicURL:    "https://sre.example.com",
		SecretValues: []string{"super-secret-token"},
	})
	if err != nil {
		t.Fatalf("NewAlertmanagerNotifier() error = %v", err)
	}
	now := time.Date(2026, 11, 18, 7, 0, 0, 0, time.UTC)
	am.now = func() time.Time { return now }

	issues := []*scanner.Issue{
		{
			ID:                "ingress-nginx/Service/ingress-nginx-controller/HealthCheck",
			Namespace:         "ingress-nginx",
			Kind:              "Service",
			Name:              "ingress-nginx-controller",
			Severity:          scanner.SeverityCritical,
			Category:          scanner.CategoryServiceHealthCheck,
			Group:             scanner.GroupFailures,
			Summary:           "Service ingress-nginx-controller healthCheckNodePort 31543 is disabled by Cilium CNI config",
			Details:           "token=super-secret-token Cilium enable-health-check-nodeport=false",
			FoldKey:           "fold-svc-health",
			OccurrenceCount:   1,
			AffectedResources: []string{"ingress-nginx/ingress-nginx-controller"},
		},
		{
			// Passive security posture should not page when IncludePosture is false.
			Namespace: "kube-system", Kind: "Pod", Name: "cilium-1",
			Severity: scanner.SeverityCritical, Category: scanner.CategorySecurityClusterBinding,
			Summary: "system cluster-admin", FoldKey: "fold-rbac",
		},
		{
			// Medium severity below HIGH threshold should not page.
			Namespace: "default", Kind: "Pod", Name: "web-0",
			Severity: scanner.SeverityMedium, Category: scanner.CategoryPodLogError,
			Summary: "minor error", FoldKey: "fold-med",
		},
	}

	if err := am.SyncFoldedIssues(context.Background(), issues, true); err != nil {
		t.Fatalf("SyncFoldedIssues(initial) error = %v", err)
	}

	// Partial scoped scan for another namespace must NOT resolve the existing alert.
	now = now.Add(time.Minute)
	otherHigh := []*scanner.Issue{{
		ID: "ctrl/Pod/sync/Log", Namespace: "cluster-config-controller", Kind: "Pod", Name: "cluster-sync-controller-0",
		Severity: scanner.SeverityHigh, Category: scanner.CategoryPodLogError, Group: scanner.GroupErrors,
		Summary: "unable to construct NLB client", Details: "OCI NLB discovery failed",
		LogsSnippet: "unable to construct NLB client", FoldKey: "fold-ctrl-log", OccurrenceCount: 2,
		Parent: &scanner.ResourceRef{Namespace: "cluster-config-controller", Kind: "Deployment", Name: "cluster-sync-controller"},
	}}
	if err := am.SyncFoldedIssues(context.Background(), otherHigh, false); err != nil {
		t.Fatalf("SyncFoldedIssues(partial) error = %v", err)
	}

	// Full cluster scan returning empty clears BOTH active alerts with EndsAt == now.
	now = now.Add(time.Minute)
	if err := am.SyncFoldedIssues(context.Background(), nil, true); err != nil {
		t.Fatalf("SyncFoldedIssues(resolved) error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 3 {
		t.Fatalf("alertmanager received %d POSTs, want 3", len(requests))
	}
	if len(requests[0]) != 1 {
		t.Fatalf("first POST sent %d alerts, want 1 filtered alert: %#v", len(requests[0]), requests[0])
	}
	first := requests[0][0]
	if first.Labels["component"] != "kubebee-sre" || first.Labels["severity"] != "critical" {
		t.Fatalf("unexpected alert labels: %#v", first.Labels)
	}
	if strings.Contains(first.Annotations["description"], "super-secret-token") {
		t.Fatalf("alert leaked configured secret: %s", first.Annotations["description"])
	}
	if !first.EndsAt.After(first.StartsAt) {
		t.Fatalf("firing alert EndsAt (%s) <= StartsAt (%s)", first.EndsAt, first.StartsAt)
	}
	if len(requests[2]) != 2 {
		t.Fatalf("resolved POST sent %d alerts, want 2 resolved alerts", len(requests[2]))
	}
	for _, resolved := range requests[2] {
		if !resolved.EndsAt.Equal(now) {
			t.Fatalf("resolved alert %s EndsAt = %s, want %s", resolved.Labels["fold_key"], resolved.EndsAt, now)
		}
	}
}
