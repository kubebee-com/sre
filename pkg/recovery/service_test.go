package recovery

import (
	"github.com/kubebee-com/sre/pkg/incident"
	"testing"
	"time"
)

func TestSustainedRecoveryCannotUseMissingPartialOrChangedSource(t *testing.T) {
	at := time.Now()
	p := incident.RecoveryProfile{WindowSeconds: 60, MaximumGapSeconds: 35, MinimumSamples: 3, MinimumReadyReplicas: 1}
	good := []incident.HealthSample{{At: at, Healthy: true, Coverage: "COMPLETE", UID: "u", AgentID: "a", Generation: 1, Epoch: "e", ReadyReplicas: 2}, {At: at.Add(-30 * time.Second), Healthy: true, Coverage: "COMPLETE", UID: "u", AgentID: "a", Generation: 1, Epoch: "e", ReadyReplicas: 2}, {At: at.Add(-60 * time.Second), Healthy: true, Coverage: "COMPLETE", UID: "u", AgentID: "a", Generation: 1, Epoch: "e", ReadyReplicas: 2}}
	if status, _ := AssessWindow(p, good, at); status != "RECOVERED" {
		t.Fatal("sustained window rejected", status)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]incident.HealthSample) []incident.HealthSample
	}{{"missing", func(s []incident.HealthSample) []incident.HealthSample { return s[:1] }}, {"partial", func(s []incident.HealthSample) []incident.HealthSample { s[1].Coverage = "PARTIAL"; return s }}, {"gap", func(s []incident.HealthSample) []incident.HealthSample { return []incident.HealthSample{s[0], s[2]} }}, {"changed-generation", func(s []incident.HealthSample) []incident.HealthSample { s[1].Generation = 2; return s }}, {"unhealthy", func(s []incident.HealthSample) []incident.HealthSample { s[1].Healthy = false; return s }}, {"old", func(s []incident.HealthSample) []incident.HealthSample {
		for i := range s {
			s[i].At = s[i].At.Add(-time.Minute)
		}
		return s
	}}} {
		t.Run(tc.name, func(t *testing.T) {
			samples := tc.mutate(append([]incident.HealthSample(nil), good...))
			if status, _ := AssessWindow(p, samples, at); status == "RECOVERED" {
				t.Fatal("unsafe recovery")
			}
		})
	}
}
