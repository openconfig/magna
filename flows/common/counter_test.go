package common

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmi/value"
	"github.com/openconfig/ygot/testutil"
	"github.com/openconfig/ygot/ygot"
)

func TestFlowUpdateTX(t *testing.T) {
	tests := []struct {
		desc       string
		inCounters *counters
		inPPS      int
		inSize     int
		want       *counters
	}{{
		desc:       "tx: packet counters initialised",
		inCounters: NewCounters(),
		inPPS:      10,
		inSize:     100,
		want: &counters{
			Tx: &stats{
				Rate:   &val{ts: 42, f: 10},
				Octets: &val{ts: 42, u: 1000},
				Pkts:   &val{ts: 42, u: 10},
			},
			Rx: &stats{},
		},
	}, {
		desc: "tx: append to existing packet count",
		inCounters: &counters{
			Tx: &stats{
				Rate:   &val{ts: 1, f: 100},
				Octets: &val{ts: 1, u: 200},
				Pkts:   &val{ts: 1, u: 300},
			},
		},
		inPPS:  100,
		inSize: 20,
		want: &counters{
			Tx: &stats{
				Rate:   &val{ts: 42, f: 100},
				Octets: &val{ts: 42, u: 2200},
				Pkts:   &val{ts: 42, u: 400},
			},
		},
	}}

	ft := func() int64 { return 42 }

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			flowTimeFn = ft

			got := NewCounters()
			if tt.inCounters != nil {
				got = tt.inCounters
			}

			got.updateTx(tt.inPPS, tt.inSize)

			if diff := cmp.Diff(got, tt.want, cmpopts.IgnoreUnexported(stats{}), cmpopts.IgnoreUnexported(counters{}), cmp.AllowUnexported(val{})); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
	flowTimeFn = unixTS
}

func TestFlowUpdateRX(t *testing.T) {
	type pktArrival struct {
		t time.Time
		s int
	}

	tests := []struct {
		desc       string
		inCounters *counters
		inPackets  []pktArrival
		want       *counters
	}{{
		desc: "single packet arriving",
		inPackets: []pktArrival{{
			t: time.Unix(1, 0),
			s: 10,
		}},
		want: &counters{
			Tx: &stats{},
			Rx: &stats{
				Octets: &val{ts: 1e9, u: 10},
				Pkts:   &val{ts: 1e9, u: 1},
			},
			Timeseries: map[int64]int{1: 10},
		},
	}, {
		desc: "multiple packets, same second",
		inPackets: []pktArrival{{
			t: time.Unix(1, 0),
			s: 10,
		}, {
			t: time.Unix(1, 0),
			s: 20,
		}},
		want: &counters{
			Tx: &stats{},
			Rx: &stats{
				Octets: &val{ts: 1e9, u: 30},
				Pkts:   &val{ts: 1e9, u: 2},
			},
			Timeseries: map[int64]int{1: 30},
		},
	}, {
		desc: "multiple packets, different seconds",
		inPackets: []pktArrival{{
			t: time.Unix(1, 0),
			s: 10,
		}, {
			t: time.Unix(2, 0),
			s: 20,
		}, {
			t: time.Unix(2, 1),
			s: 10,
		}},
		want: &counters{
			Tx: &stats{},
			Rx: &stats{
				Octets: &val{ts: 2e9 + 1, u: 40},
				Pkts:   &val{ts: 2e9 + 1, u: 3},
			},
			Timeseries: map[int64]int{
				1: 10,
				2: 30,
			},
		},
	}, {
		desc: "append to existing data",
		inCounters: &counters{
			Rx: &stats{
				Octets: &val{ts: 1e9, u: 4000},
				Pkts:   &val{ts: 1e9, u: 200},
			},
			Timeseries: map[int64]int{
				1: 200,
			},
		},
		inPackets: []pktArrival{{
			t: time.Unix(1, 1),
			s: 10,
		}, {
			t: time.Unix(2, 1),
			s: 20,
		}},
		want: &counters{
			Rx: &stats{
				Octets: &val{ts: 2e9 + 1, u: 4030},
				Pkts:   &val{ts: 2e9 + 1, u: 202},
			},
			Timeseries: map[int64]int{
				1: 210,
				2: 20,
			},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := NewCounters()
			if tt.inCounters != nil {
				got = tt.inCounters
			}

			for _, p := range tt.inPackets {
				got.updateRx(p.t, p.s)
			}

			if diff := cmp.Diff(got, tt.want, cmpopts.IgnoreUnexported(stats{}), cmpopts.IgnoreUnexported(counters{}), cmp.AllowUnexported(val{})); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

func TestLossPct(t *testing.T) {
	tests := []struct {
		desc string
		in   *counters
		want float32
	}{{
		desc: "no loss",
		in: &counters{
			Tx: &stats{
				Pkts: &val{ts: 1e9, u: 100},
			},
			Rx: &stats{
				Pkts: &val{ts: 1e9, u: 100},
			},
		},
		want: 0,
	}, {
		desc: "all lost",
		in: &counters{
			Tx: &stats{
				Pkts: &val{ts: 1e9, u: 200},
			},
			Rx: &stats{
				Pkts: &val{ts: 1e9, u: 0},
			},
		},
		want: 100,
	}, {
		desc: "50% loss",
		in: &counters{
			Tx: &stats{
				Pkts: &val{ts: 1e9, u: 84},
			},
			Rx: &stats{
				Pkts: &val{ts: 1e9, u: 42},
			},
		},
		want: 50,
	}, {
		desc: "1/3 lost",
		in: &counters{
			Tx: &stats{
				Pkts: &val{ts: 1e9, u: 3},
			},
			Rx: &stats{
				Pkts: &val{ts: 1e9, u: 2},
			},
		},
		want: 1.0 / 3.0 * 100.0,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if got := tt.in.lossPct(); !cmp.Equal(got, tt.want, cmpopts.EquateApprox(0.01, 0)) {
				t.Fatalf("did not get expected loss, got: %.3f, want: %.3f", got, tt.want)
			}
		})
	}
}

func TestRxRate(t *testing.T) {
	tests := []struct {
		desc string
		in   *counters
		want float32
	}{{
		desc: "full sliding window",
		in: &counters{
			Timeseries: map[int64]int{
				1: 10,
				2: 10,
				3: 10,
				4: 10,
				5: 10,
				6: 10,
			},
		},
		want: 80.0,
	}, {
		desc: "single entry",
		in: &counters{
			Timeseries: map[int64]int{
				1: 10,
			},
		},
		want: 0,
	}, {
		desc: "no entries",
		in:   &counters{},
		want: 0,
	}, {
		desc: "fewer than sliding window entries",
		in: &counters{
			Timeseries: map[int64]int{
				1: 10,
				2: 10,
				3: 10,
			},
		},
		want: 80.0,
	}, {
		desc: "average required",
		in: &counters{
			Timeseries: map[int64]int{
				1: 10,
				2: 20,
				3: 15,
				4: 20,
				5: 17,
				6: 18,
				7: 19,
				8: 22,
			},
		},
		want: float32(19+18+17+20+15) / 5.0 * 8.0,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if got := tt.in.rxRate(); !cmp.Equal(got, tt.want, cmpopts.EquateApprox(0.01, 0)) {
				t.Fatalf("did not get expected rate, got: %.3f, want: %.3f", got, tt.want)
			}
		})
	}
}

type updSpec struct {
	path string
	val  any
}

func mustNoti(t *testing.T, target string, ts int64, upd ...updSpec) *gpb.Notification {
	t.Helper()

	updates := []*gpb.Update{}
	for _, in := range upd {
		p, err := ygot.StringToStructuredPath(in.path)
		if err != nil {
			t.Fatalf("did not get valid path, got: %s, err: %v", in.path, err)
		}

		u := &gpb.Update{Path: p}
		switch vv := in.val.(type) {
		case *gpb.TypedValue:
			u.Val = vv
		default:
			v, err := value.FromScalar(in.val)
			if err != nil {
				t.Fatalf("cannot make value into TypedValue, got: %v, err: %v", in.val, err)
			}
			u.Val = v
		}
		updates = append(updates, u)
	}

	return &gpb.Notification{
		Prefix: &gpb.Path{
			Origin: "openconfig",
			Target: target,
		},
		Timestamp: ts,
		Update:    updates,
	}
}

func TestTelemetry(t *testing.T) {
	tests := []struct {
		desc     string
		in       *counters
		inTarget string
		want     []*gpb.Notification
	}{{
		desc: "empty input",
		in:   NewCounters(),
	}, {
		desc: "tx statistics",
		in: &counters{
			Name: &val{ts: 1, s: "flow_one"},
			Tx: &stats{
				Pkts:   &val{ts: 100, u: 100},
				Octets: &val{ts: 100, u: 800},
				Rate:   &val{ts: 100, f: 8000},
			},
			Transmit: &val{ts: 120, b: true},
		},
		inTarget: "dut",
		want: []*gpb.Notification{
			mustNoti(t, "dut", 1,
				updSpec{path: "/flows/flow[name=flow_one]/name", val: "flow_one"},
				updSpec{path: "/flows/flow[name=flow_one]/state/name", val: "flow_one"}),
			mustNoti(t, "dut", 120, updSpec{path: "/flows/flow[name=flow_one]/state/transmit", val: true}),
			mustNoti(t, "dut", 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/out-pkts", val: uint64(100)}),
			mustNoti(t, "dut", 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/out-octets", val: uint64(800)}),
			mustNoti(t, "dut", 100, updSpec{path: "/flows/flow[name=flow_one]/state/out-rate", val: []byte{0, 0, 250, 69}}),
		},
	}, {
		desc: "rx statistics",
		in: &counters{
			Name: &val{ts: 1, s: "flow_one"},
			Rx: &stats{
				Pkts:   &val{ts: 100, u: 100},
				Octets: &val{ts: 100, u: 800},
			},
			Transmit: &val{ts: 120, b: true},
		},
		inTarget: "dut",
		want: []*gpb.Notification{
			mustNoti(t, "dut", 1,
				updSpec{path: "/flows/flow[name=flow_one]/name", val: "flow_one"},
				updSpec{path: "/flows/flow[name=flow_one]/state/name", val: "flow_one"}),
			mustNoti(t, "dut", 120, updSpec{path: "/flows/flow[name=flow_one]/state/transmit", val: true}),
			mustNoti(t, "dut", 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/in-pkts", val: uint64(100)}),
			mustNoti(t, "dut", 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/in-octets", val: uint64(800)}),
			mustNoti(t, "dut", 42, updSpec{path: "/flows/flow[name=flow_one]/state/in-rate", val: []byte{0, 0, 0, 0}}),
		},
	}, {
		desc: "tx and rx",
		in: &counters{
			Name: &val{ts: 1, s: "flow_one"},
			Tx: &stats{
				Pkts:   &val{ts: 100, u: 100},
				Octets: &val{ts: 100, u: 800},
				Rate:   &val{ts: 100, f: 8000},
			},
			Transmit: &val{ts: 120, b: true},
			Rx: &stats{
				Pkts:   &val{ts: 100, u: 0},
				Octets: &val{ts: 100, u: 800},
			},
			Timeseries: map[int64]int{
				10: 20,
				20: 20,
				30: 20,
				40: 20,
				50: 20,
				60: 20,
			},
		},
		inTarget: "ate",
		want: []*gpb.Notification{
			mustNoti(t, "ate", 1,
				updSpec{path: "/flows/flow[name=flow_one]/name", val: "flow_one"},
				updSpec{path: "/flows/flow[name=flow_one]/state/name", val: "flow_one"}),
			mustNoti(t, "ate", 120, updSpec{path: "/flows/flow[name=flow_one]/state/transmit", val: true}),
			mustNoti(t, "ate", 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/out-pkts", val: uint64(100)}),
			mustNoti(t, "ate", 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/out-octets", val: uint64(800)}),
			mustNoti(t, "ate", 100, updSpec{path: "/flows/flow[name=flow_one]/state/out-rate", val: []byte{0, 0, 250, 69}}),
			mustNoti(t, "ate", 120, updSpec{path: "/flows/flow[name=flow_one]/state/transmit", val: true}),
			mustNoti(t, "ate", 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/in-pkts", val: uint64(0)}),
			mustNoti(t, "ate", 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/in-octets", val: uint64(800)}),
			mustNoti(t, "ate", 42, updSpec{path: "/flows/flow[name=flow_one]/state/in-rate", val: []byte{0, 0, 128, 65}}),
			mustNoti(t, "ate", 42, updSpec{path: "/flows/flow[name=flow_one]/state/loss-pct", val: []byte{0, 0, 200, 66}}),
		},
	}}

	flowTimeFn = func() int64 { return 42 }
	defer func() { flowTimeFn = unixTS }()

	shortNoti := func(set []*gpb.Notification) string {
		var s string
		for _, n := range set {
			for _, u := range n.Update {
				p, err := ygot.PathToString(u.Path)
				if err != nil {
					t.Fatalf("invalid path in Notification, got: %v, err: %v", u.Path, err)
				}
				v, err := value.ToScalar(u.Val)
				if err != nil {
					t.Fatalf("invalid value in Notification, got: %v, err: %v", u.Val, err)
				}

				s += fmt.Sprintf("%d: %s:%s: %v\n", n.Timestamp, n.GetPrefix().GetTarget(), p, v)
			}
		}
		return s
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if got := tt.in.telemetry(tt.inTarget); !testutil.NotificationSetEqual(got, tt.want) {
				t.Fatalf("did not get expected set of notifications, got: \n%s\nwant:\n%s", shortNoti(got), shortNoti(tt.want))
			}
		})
	}
}

func TestClearStats(t *testing.T) {
	tests := []struct {
		desc string
		in   *counters
		inTS int64
		want *counters
	}{{
		desc: "nil Tx, Rx",
		in:   &counters{},
		inTS: 42,
		want: &counters{
			Tx: &stats{
				Pkts:   &val{ts: 42, u: 0},
				Octets: &val{ts: 42, u: 0},
				Rate:   &val{ts: 42, f: 0.0},
			},
			Rx: &stats{
				Pkts:   &val{ts: 42, u: 0},
				Octets: &val{ts: 42, u: 0},
				Rate:   &val{ts: 42, f: 0.0},
			},
		},
	}, {
		desc: "empty Tx, Rx",
		in:   NewCounters(),
		inTS: 42,
		want: &counters{
			Tx: &stats{
				Pkts:   &val{ts: 42, u: 0},
				Octets: &val{ts: 42, u: 0},
				Rate:   &val{ts: 42, f: 0.0},
			},
			Rx: &stats{
				Pkts:   &val{ts: 42, u: 0},
				Octets: &val{ts: 42, u: 0},
				Rate:   &val{ts: 42, f: 0.0},
			},
		},
	}, {
		desc: "populated",
		in: &counters{
			Tx: &stats{
				Pkts:   &val{ts: 21, u: 4},
				Octets: &val{ts: 22, u: 2},
				Rate:   &val{ts: 33, f: 4.2},
			},
			Rx: &stats{
				Pkts:   &val{ts: 12, u: 2},
				Octets: &val{ts: 18, u: 40},
				Rate:   &val{ts: 9, f: 4.0},
			},
		},
		inTS: 42,
		want: &counters{
			Tx: &stats{
				Pkts:   &val{ts: 42, u: 0},
				Octets: &val{ts: 42, u: 0},
				Rate:   &val{ts: 42, f: 0.0},
			},
			Rx: &stats{
				Pkts:   &val{ts: 42, u: 0},
				Octets: &val{ts: 42, u: 0},
				Rate:   &val{ts: 42, f: 0.0},
			},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			tt.in.clearStats(tt.inTS)
			if diff := cmp.Diff(tt.in, tt.want,
				cmp.AllowUnexported(stats{}),
				cmp.AllowUnexported(val{}),
				cmpopts.IgnoreTypes(sync.RWMutex{}),
				cmpopts.IgnoreTypes(sync.Mutex{}),
			); diff != "" {
				t.Fatalf("(flowCounters).clearStats(): did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
}
