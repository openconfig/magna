package common

import (
	"encoding/binary"
	"math"
	"sort"
	"sync"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/google/gopacket"
	"github.com/openconfig/magna/otgyang"
	tcommon "github.com/openconfig/magna/telemetry/common"
	"github.com/openconfig/ygot/ygot"
	"k8s.io/klog/v2"
)

var (
	// unixTS returns the current time in nanoseconds since the unix epoch.
	unixTS = func() int64 { return time.Now().UnixNano() }
	// flowTimeFn is a function that can be overloaded that specifies how the timestamp
	// is retrieved.
	flowTimeFn = unixTS
)

// counters is an internal data store for parameters that are sent as part of the
// OTG telemetry for the flow.
type counters struct {
	// Name is the name of the flow.
	Name *val

	// Headers is the set of headers expected for packets matching this flow.
	Headers []gopacket.SerializableLayer

	mu sync.RWMutex
	// tx and rx store the counters for statistics relating to the flow.
	Tx, Rx *stats
	// transmit indicates whether the flow is currently transmitting.
	Transmit *val

	// tsMu protects the Timeseries map.
	tsMu sync.RWMutex
	// Timeseries maps a unix timestamp (in seconds) to an integer number of packets
	// received in that interval for rate calculation.
	Timeseries map[int64]int
}

func NewCounters() *counters {
	return &counters{
		Tx: &stats{},
		Rx: &stats{},
	}
}

// GetName returns the name of the flow.
func (f *counters) GetName() string {
	if f.Name == nil {
		return ""
	}
	return f.Name.s
}

// updateTx updates the transmit counters for the flow according to the specified
// packets per second rate and packet size.
func (f *counters) updateTx(pps, size int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	txStats := f.Tx

	now := flowTimeFn()

	txStats.Rate = &val{ts: now, f: float32(pps)}

	if txStats.Octets == nil {
		txStats.Octets = &val{}
	}

	txStats.Octets.u += uint64(pps) * uint64(size)
	txStats.Octets.ts = now

	if txStats.Pkts == nil {
		txStats.Pkts = &val{}
	}

	txStats.Pkts.u += uint64(pps)
	txStats.Pkts.ts = now
}

// updateRx updates counters for received packets. It is to be called for each
// received packet with the timestamp of the arrival, and the packet size.
// In addition to updating the stats, it records a timeseries of received packets
// to allow for rate calculation.
func (f *counters) updateRx(ts time.Time, size int) {
	f.tsMu.Lock()
	defer f.tsMu.Unlock()
	if f.Timeseries == nil {
		f.Timeseries = map[int64]int{}
	}
	f.Timeseries[ts.Unix()] += size

	f.mu.Lock()
	defer f.mu.Unlock()
	rxStats := f.Rx

	if rxStats.Octets == nil {
		rxStats.Octets = &val{}
	}
	rxStats.Octets.u += uint64(size)
	rxStats.Octets.ts = ts.UnixNano()

	if rxStats.Pkts == nil {
		f.Rx.Pkts = &val{}
	}
	rxStats.Pkts.u += 1
	rxStats.Pkts.ts = ts.UnixNano()
}

func (f *counters) setTransmit(state bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Transmit == nil {
		f.Transmit = &val{}
	}
	f.Transmit.b = state
	f.Transmit.ts = time.Now().UnixNano()
}

// clearStats zeros the stastitics for the flow.
func (f *counters) clearStats(ts int64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.Tx = &stats{
		Octets: &val{ts: ts, u: 0},
		Pkts:   &val{ts: ts, u: 0},
		Rate:   &val{ts: ts, f: 0.0},
	}
	f.Rx = &stats{
		Octets: &val{ts: ts, u: 0},
		Pkts:   &val{ts: ts, u: 0},
		Rate:   &val{ts: ts, f: 0.0},
	}
}

// lossPct calculates the percentage loss that the flow has experienced.
func (f *counters) lossPct(txPkts, rxPkts uint64) float32 {
	return float32(txPkts-rxPkts) / float32(txPkts) * 100.0
}

const (
	// slidingWindow specifies the number of seconds over which to calculate the rate
	// of the flow.
	slidingWindow int = 5
)

// currentRate calculates the current received rate based on the sliding window
// size specified. It returns the rate it bits per second.
func (f *counters) rxRate() float32 {
	f.tsMu.Lock()
	defer f.tsMu.Unlock()
	keys := []int{}
	for k := range f.Timeseries {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	if len(keys) == 0 || len(keys) == 1 {
		// If we do not have enough datapoints to calculate the rate then return 0.0
		return 0.0
	}

	firstEntry := 0
	if len(keys) > slidingWindow {
		firstEntry = len(keys) - slidingWindow - 1
	}

	var sum int
	// Ignore the last slot since we may still be appending to it.
	for i := firstEntry; i < len(keys)-1; i++ {
		sum += f.Timeseries[int64(keys[i])]
	}
	// calculate the time delta over which these entries were calculated.
	delta := float32(keys[int64(len(keys)-1)]) - float32(keys[firstEntry])

	// Average the rate and return in bits per second rather than bytes.
	return float32(sum) / delta * 8.0
}

type datapoint struct {
	d  *otgyang.Device
	ts int64
}

// datapoints returns the set of telemetry updates with timestamps that need to be sent for this flow.
//
// TODO(robjs): with sufficient numbers of flows, then this function ends up holding the f.mu lock regularly
// and causing lock contention with packets that are being sent and received.
// To avoid the lock contention an alternate approach is needed. Particularly,
// either batch updates from the Tx/Rx goroutines, or push updates from the
// Tx/Rx goroutines.
func (f *counters) datapoints() (string, []*datapoint) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Cannot generate statistics until the flow is initialised with a name.
	if f.Name == nil {
		return "", nil
	}
	name := f.Name.s

	upd := []*datapoint{}

	if f.Transmit != nil {
		t := &otgyang.Device{}
		t.GetOrCreateFlow(name).Transmit = ygot.Bool(f.Transmit.b)
		upd = append(upd, &datapoint{d: t, ts: f.Transmit.ts})
	}
	if f.Tx != nil && f.Rx != nil {
		if f.Tx.Pkts != nil && f.Rx.Pkts != nil {
			l := &otgyang.Device{}
			l.GetOrCreateFlow(name).LossPct = float32ToBinary(f.lossPct(f.Tx.Pkts.u, f.Rx.Pkts.u))
			upd = append(upd, &datapoint{d: l, ts: flowTimeFn()})
		}
	}

	if f.Tx != nil {
		txStats := f.Tx
		if txStats.Octets != nil {
			// TX statistics
			txo := &otgyang.Device{}
			txo.GetOrCreateFlow(name).GetOrCreateCounters().OutOctets = ygot.Uint64(txStats.Octets.u)
			upd = append(upd, &datapoint{d: txo, ts: txStats.Octets.ts})
		}

		if txStats.Pkts != nil {
			tp := &otgyang.Device{}
			tp.GetOrCreateFlow(name).GetOrCreateCounters().OutPkts = ygot.Uint64(txStats.Pkts.u)
			upd = append(upd, &datapoint{d: tp, ts: txStats.Pkts.ts})
		}
		if txStats.Rate != nil {
			tr := &otgyang.Device{}
			tr.GetOrCreateFlow(name).OutRate = float32ToBinary(txStats.Rate.f)
			upd = append(upd, &datapoint{d: tr, ts: txStats.Rate.ts})
		}
	}

	if f.Rx != nil {
		// RX statistics
		rxStats := f.Rx

		if rxStats.Octets != nil {
			r := &otgyang.Device{}
			r.GetOrCreateFlow(name).GetOrCreateCounters().InOctets = ygot.Uint64(rxStats.Octets.u)
			upd = append(upd, &datapoint{d: r, ts: rxStats.Octets.ts})
		}
		if rxStats.Pkts != nil {
			rp := &otgyang.Device{}
			rp.GetOrCreateFlow(name).GetOrCreateCounters().InPkts = ygot.Uint64(rxStats.Pkts.u)
			upd = append(upd, &datapoint{d: rp, ts: rxStats.Pkts.ts})
		}
		rr := &otgyang.Device{}
		rr.GetOrCreateFlow(name).InRate = float32ToBinary(f.rxRate()) // express in bits per second rather than bytes
		upd = append(upd, &datapoint{d: rr, ts: flowTimeFn()})
	}

	return name, upd
}

// telemetry generates the set of gNMI Notifications that describes the flow's current state.
// The target argument specifies the Target value that should be included in the notifications.
func (f *counters) telemetry(target string) []*gpb.Notification {
	// Call datapoints to avoid holding the counters.mu mutex longer than we need to.
	name, upd := f.datapoints()
	if name == "" {
		return nil
	}
	notis := []*gpb.Notification{}
	for _, u := range upd {
		notifications, err := ygot.TogNMINotifications(u.d, u.ts, ygot.GNMINotificationsConfig{UsePathElem: true})
		if err != nil {
			klog.Errorf("cannot render stats to notification, input: %v, err: %v", u, err)
			continue
		}

		for _, n := range notifications {
			// TODO(robjs): This is a hack, we need to remove the additional flow name updates. ygot.TogNMINotifications
			// needs a path filter to avoid duplicating leaves, or a way to store timestamps per-leaf. Length 3 means we
			// the name, state/name, and then one other leaf.
			if len(n.Update) == 3 {
				nn := &gpb.Notification{Timestamp: n.Timestamp}
				for _, u := range n.Update {
					if len(u.Path.Elem) == 3 || len(u.Path.Elem) == 4 {
						if u.Path.Elem[len(u.Path.Elem)-1].Name == "name" {
							continue
						}
					}
					nn.Update = append(nn.Update, u)
				}
				notis = append(notis, tcommon.AddTarget(nn, target))
			}
		}
	}

	nameUpd := &otgyang.Device{}
	nameUpd.GetOrCreateFlow(name)
	n, err := ygot.TogNMINotifications(nameUpd, f.Name.ts, ygot.GNMINotificationsConfig{UsePathElem: true})
	if err != nil {
		klog.Errorf("cannot render name notification, got err: %v", err)
	}
	for _, u := range n {
		notis = append(notis, tcommon.AddTarget(u, target))
	}

	return notis
}

// float32ToBinary converts a float32 value into IEEE754 representation
// and converts it to the generated ygot type for use in generated structs.
func float32ToBinary(f float32) otgyang.Binary {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, math.Float32bits(f))
	return otgyang.Binary(b)
}
