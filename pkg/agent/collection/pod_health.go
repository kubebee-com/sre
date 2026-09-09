package collection

import (
	core "k8s.io/api/core/v1"
	"time"
)

// PodRestarting recognizes both backoff and the terminated state between retries.
// It establishes a symptom only; it cannot establish a cause or recovery.
func PodRestarting(p *core.Pod, at time.Time) bool {
	for _, s := range append(append([]core.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if s.State.Waiting != nil && s.State.Waiting.Reason == "CrashLoopBackOff" {
			return true
		}
		if s.State.Terminated != nil && s.RestartCount >= 2 && p.Spec.RestartPolicy == core.RestartPolicyAlways {
			finished := s.State.Terminated.FinishedAt.Time
			if !finished.IsZero() && !finished.After(at) && at.Sub(finished) <= 90*time.Second {
				return true
			}
		}
	}
	return false
}
