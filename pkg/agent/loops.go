package agent

import "context"

type loop interface{ Run(context.Context) error }
type loopFunc func(context.Context) error

func (f loopFunc) Run(ctx context.Context) error { return f(ctx) }

// runLoops drains every worker before releasing shared runtime resources.
func runLoops(ctx context.Context, workers []loop) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(workers))
	for _, worker := range workers {
		go func(w loop) { results <- w.Run(ctx) }(worker)
	}
	var first error
	for range workers {
		err := <-results
		if err != nil && first == nil {
			first = err
		}
		cancel()
	}
	return first
}
