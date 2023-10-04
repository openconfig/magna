package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestReporter(t *testing.T) {
	tests := []struct {
		desc        string
		inFlows     []string
		wantCounter map[string]*counters
	}{
		{
			desc:    "simple",
			inFlows: []string{"one"},
			wantCounter: map[string]*counters{
				"one": nil,
			},
		},
		{
			desc:    "two flows",
			inFlows: []string{"one", "two"},
			wantCounter: map[string]*counters{
				"one": nil,
				"two": nil,
			},
		},
		{
			desc:    "repeat flows",
			inFlows: []string{"one", "two", "two"},
			wantCounter: map[string]*counters{
				"one": nil,
				"two": nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			r := NewReporter()
			for _, f := range tt.inFlows {
				r.AddFlow(f, nil)
			}

			less := func(left, right string) bool {
				return left < right
			}

			if diff := cmp.Diff(r.counters, tt.wantCounter, cmpopts.SortMaps(less)); diff != "" {
				t.Errorf("Reporter did not contains the right counters (-got, +want):\n%s", diff)
			}
		})
	}
}
