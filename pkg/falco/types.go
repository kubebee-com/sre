// Package falco provides event models, sanitization, and ingestion for Falco runtime security.
package falco

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/kubebee-com/sre/pkg/scanner"
)

// Priority represents the severity level assigned by Falco.
type Priority string

const (
	PriorityEmergency     Priority = "Emergency"
	PriorityAlert         Priority = "Alert"
	PriorityCritical      Priority = "Critical"
	PriorityError         Priority = "Error"
	PriorityWarning       Priority = "Warning"
	PriorityNotice        Priority = "Notice"
	PriorityInformational Priority = "Informational"
	PriorityDebug         Priority = "Debug"
)

// Event represents a parsed event emitted by Falco or Falcosidekick.
type Event struct {
	UUID         string                 `json:"uuid,omitempty"`
	Output       string                 `json:"output"`
	Priority     Priority               `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	Source       string                 `json:"source,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
	OutputFields map[string]interface{} `json:"output_fields,omitempty"`
	Hostname     string                 `json:"hostname,omitempty"`
}

var (
	podRegex = regexp.MustCompile(`(?:k8s\.pod(?:_name)?|pod(?:_name)?)=([a-zA-Z0-9][-a-zA-Z0-9_.]*)`)
	nsRegex  = regexp.MustCompile(`(?:k8s\.ns(?:_name)?|namespace)=([a-zA-Z0-9][-a-zA-Z0-9_.]*)`)
)

// Namespace extracts the Kubernetes namespace associated with this event.
func (e *Event) Namespace() string {
	if e == nil {
		return ""
	}
	if e.OutputFields != nil {
		for _, key := range []string{"k8s.ns.name", "k8s.ns", "namespace"} {
			if val, ok := e.OutputFields[key]; ok {
				if str, ok := val.(string); ok && str != "" {
					return str
				}
			}
		}
	}
	if matches := nsRegex.FindStringSubmatch(e.Output); len(matches) > 1 {
		return matches[1]
	}
	return "default"
}

// PodName extracts the Kubernetes pod name associated with this event.
func (e *Event) PodName() string {
	if e == nil {
		return ""
	}
	if e.OutputFields != nil {
		for _, key := range []string{"k8s.pod.name", "k8s.pod", "pod.name", "pod"} {
			if val, ok := e.OutputFields[key]; ok {
				if str, ok := val.(string); ok && str != "" {
					return str
				}
			}
		}
	}
	if matches := podRegex.FindStringSubmatch(e.Output); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ContainerID extracts the container ID.
func (e *Event) ContainerID() string {
	if e == nil || e.OutputFields == nil {
		return ""
	}
	for _, key := range []string{"container.id", "k8s.container.id"} {
		if val, ok := e.OutputFields[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

// ProcessName extracts process or command line context.
func (e *Event) ProcessName() string {
	if e == nil || e.OutputFields == nil {
		return ""
	}
	for _, key := range []string{"proc.cmdline", "proc.name", "proc.pname"} {
		if val, ok := e.OutputFields[key]; ok {
			if str, ok := val.(string); ok && str != "" {
				return str
			}
		}
	}
	return ""
}

// IsCritical returns true if the event requires urgent operator intervention.
func (e *Event) IsCritical() bool {
	if e == nil {
		return false
	}
	switch strings.ToLower(string(e.Priority)) {
	case "emergency", "alert", "critical":
		return true
	default:
		return false
	}
}

// ScannerSeverity converts Falco Priority to standard KubeBee scanner Severity.
func (e *Event) ScannerSeverity() scanner.Severity {
	if e == nil {
		return scanner.SeverityLow
	}
	switch strings.ToLower(string(e.Priority)) {
	case "emergency", "alert", "critical":
		return scanner.SeverityCritical
	case "error":
		return scanner.SeverityHigh
	case "warning":
		return scanner.SeverityMedium
	default:
		return scanner.SeverityLow
	}
}

// SuggestedRemediation returns the recommended SRE action code for this security event.
func (e *Event) SuggestedRemediation() string {
	if e == nil {
		return "Manual"
	}
	ruleLower := strings.ToLower(e.Rule)
	// Kernel/host level threat or escape indicates node cordon
	if strings.Contains(ruleLower, "kernel") || strings.Contains(ruleLower, "escape") || strings.Contains(ruleLower, "cgroup") {
		return "CordonNode"
	}
	// Malicious process, reverse shell, or binary injection inside container indicates pod replacement
	if strings.Contains(ruleLower, "shell") || strings.Contains(ruleLower, "binary") || strings.Contains(ruleLower, "reverse") ||
		strings.Contains(ruleLower, "privilege") || strings.Contains(ruleLower, "crypto") {
		if e.PodName() != "" {
			return "RestartPod"
		}
	}
	return "Manual"
}

// UnmarshalEvent parses a raw Falco JSON byte slice into an Event struct.
func UnmarshalEvent(data []byte) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, err
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	return &ev, nil
}
