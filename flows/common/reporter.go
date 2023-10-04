package common

import (
	"sync"

	"github.com/openconfig/magna/lwotgtelem/gnmit"
)

// Reporter encapsulates multiple named flows.
type Reporter struct {
	mu sync.RWMutex
	// counters is a map of counters, keyed by the flow name, for each flow.
	counters map[string]*counters
}

// NewReporter returns a new flow reporter.
func NewReporter() *Reporter {
	return &Reporter{
		counters: map[string]*counters{},
	}
}

func (r *Reporter) Telemetry(updateFn gnmit.UpdateFn, target string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, f := range r.counters {
		for _, u := range f.telemetry(target) {
			updateFn(u)
		}
	}
}






