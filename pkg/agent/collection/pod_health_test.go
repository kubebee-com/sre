package collection

import (
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
	"time"
)

func TestRecentRepeatedTerminationIsARestartingSymptom(t *testing.T) {
	at := time.Now()
	p := &core.Pod{Spec: core.PodSpec{RestartPolicy: core.RestartPolicyAlways}, Status: core.PodStatus{ContainerStatuses: []core.ContainerStatus{{RestartCount: 3, State: core.ContainerState{Terminated: &core.ContainerStateTerminated{FinishedAt: meta.NewTime(at.Add(-time.Second))}}}}}}
	if !PodRestarting(p, at) {
		t.Fatal("recent repeated termination missed")
	}
	p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = meta.NewTime(at.Add(-2 * time.Minute))
	if PodRestarting(p, at) {
		t.Fatal("old termination treated as current")
	}
	p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = meta.NewTime(at)
	p.Spec.RestartPolicy = core.RestartPolicyNever
	if PodRestarting(p, at) {
		t.Fatal("completed one-shot considered restarting")
	}
}
