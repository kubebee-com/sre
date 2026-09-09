package privacy

import "time"

func SuggestCause(cause string, observations []Observation, at time.Time) bool {
	switch Code(cause) {
	case NetworkBlocked, ConfigurationDrift, ResourcePressure:
	default:
		return false
	}
	for _, o := range observations {
		if o.Validate() != nil || o.ObservedAt.After(at) || !o.ValidUntil.After(at) || string(o.Code) != cause {
			continue
		}
		contradicted := false
		for _, other := range observations {
			if other.ResourceHandle == o.ResourceHandle && other.Code == Healthy && other.Validate() == nil && !other.ObservedAt.After(at) && other.ValidUntil.After(at) {
				contradicted = true
			}
		}
		if !contradicted {
			return true
		}
	}
	return false
}
