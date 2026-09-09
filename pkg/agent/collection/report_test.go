package collection

import (
	"encoding/json"
	"github.com/kubebee-com/sre/pkg/privacy"
	"strings"
	"testing"
	"time"
)

func TestReportAllowsOnlyBoundedProjectedObservations(t *testing.T) {
	report := Report{ID: strings.Repeat("a", 32), ClusterUID: "cluster", ObservedAt: time.Now(), Coverage: "COMPLETE", Observations: []privacy.Observation{{Code: privacy.CrashLoop, ResourceHandle: strings.Repeat("a", 32), ObservedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute)}}}
	if report.Validate() != nil {
		t.Fatal("valid projected report rejected")
	}
	report.Coverage = "customer-email@example.com"
	if report.Validate() == nil {
		t.Fatal("free-text coverage accepted")
	}
	var decoded Report
	if DecodeReport([]byte(`{"id":"x","logs":"customer secret"}`), &decoded) == nil {
		t.Fatal("customer text accepted")
	}
	raw, _ := json.Marshal(report)
	if len(raw) == 0 {
		t.Fatal("report missing")
	}
}
