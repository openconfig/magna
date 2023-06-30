// Package mpls parses OTG flow descriptions that consist of
// MPLS packets and returns functions that can generate and receive
// packets for these flows. These can be used with the LWOTG
// implementation.
package mpls

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"github.com/openconfig/magna/flows/common"
	"github.com/openconfig/magna/lwotg"
	"github.com/openconfig/magna/lwotgtelem/gnmit"
	"github.com/openconfig/magna/otgyang"
	tcommon "github.com/openconfig/magna/telemetry/common"
	"github.com/openconfig/ygot/ygot"
	"k8s.io/klog"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

var (
	// timeout specifies how long to wait for a PCAP handle.
	pcapTimeout = 30 * time.Second
	// packetBytes is the number of bytes to read from an input packet.
	packetBytes int = 1500
)

const (
	// defaultMPLSTTL is the TTL value used by default in the MPLS header.
	defaultMPLSTTL uint8 = 64
)

// headers returns the gopacket layers for the specified flow.
func headers(f *otg.Flow) ([]gopacket.SerializableLayer, error) {
	var (
		ethernet *otg.FlowHeader
		mpls     []*otg.FlowHeader
		ip4      *otg.FlowHeader
	)

	// This package only handles MPLS packets, and there are restrictions on this. Thus we check
	// that the packet that we've been asked for is something we can generate.
	for _, layer := range f.Packet {
		switch t := layer.GetChoice(); t {
		case otg.FlowHeader_Choice_ethernet:
			if ethernet != nil {
				return nil, fmt.Errorf("multiple Ethernet layers not handled by MPLS plugin")
			}
			ethernet = layer
		case otg.FlowHeader_Choice_mpls:
			mpls = append(mpls, layer)
		case otg.FlowHeader_Choice_ipv4:
			if len(mpls) == 0 || ip4 != nil {
				return nil, fmt.Errorf("multiple IPv4, or outer IPv4 layers not handled by MPLS plugin")
			}
			ip4 = layer
		default:
			return nil, fmt.Errorf("MPLS does not handle layer %s", t)
		}
	}

	if dstT := ethernet.GetEthernet().GetDst().GetChoice(); dstT != otg.PatternFlowEthernetDst_Choice_value {
		return nil, fmt.Errorf("simple MPLS does not handle non-explicit destination MAC, got: %s", dstT)
	}
	if srcT := ethernet.GetEthernet().GetSrc().GetChoice(); srcT != otg.PatternFlowEthernetSrc_Choice_value {
		return nil, fmt.Errorf("simple MPLS does not handle non-explicit src MAC, got: %v", srcT)
	}

	srcMAC, err := net.ParseMAC(ethernet.GetEthernet().GetSrc().GetValue())
	if err != nil {
		return nil, fmt.Errorf("cannot parse source MAC, %v", err)
	}
	dstMAC, err := net.ParseMAC(ethernet.GetEthernet().GetDst().GetValue())
	if err != nil {
		return nil, fmt.Errorf("cannot parse destination MAC, %v", err)
	}

	pktLayers := []gopacket.SerializableLayer{
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeMPLSUnicast,
		},
	}

	// OTG says that the order of the layers must be the order on the wire.
	for _, m := range mpls {
		if valT := m.GetMpls().GetLabel().GetChoice(); valT != otg.PatternFlowMplsLabel_Choice_value {
			return nil, fmt.Errorf("simple MPLS does not handle labels that do not have an explicit value, got: %v", valT)
		}

		if bosT := m.GetMpls().GetBottomOfStack().GetChoice(); bosT != otg.PatternFlowMplsBottomOfStack_Choice_value {
			// TODO(robjs): It doesn't make sense here to
			// have increment value - it can be 0 or 1.
			// Possibly 'auto' should be suported. Bring
			// this up with OTG designers.
			return nil, fmt.Errorf("bottom of stack with non-explicit value requested, must be explicit, %v", bosT)
		}

		var ttl uint8
		switch ttlT := m.GetMpls().GetTimeToLive().GetChoice(); ttlT {
		case otg.PatternFlowMplsTimeToLive_Choice_value:
			ttl = uint8(m.GetMpls().GetTimeToLive().GetValue())
		case otg.PatternFlowMplsTimeToLive_Choice_unspecified:
			ttl = defaultMPLSTTL
		default:
			return nil, fmt.Errorf("simple MPLS does not handle TTLs that are not explicitly set")
		}

		ll := &layers.MPLS{
			Label:       uint32(m.GetMpls().GetLabel().GetValue()),
			TTL:         ttl,
			StackBottom: m.GetMpls().GetBottomOfStack().GetValue() == 1,
		}

		pktLayers = append(pktLayers, ll)
	}

	if ip4 != nil {

		if dstT := ip4.GetIpv4().GetDst().GetChoice(); dstT != otg.PatternFlowIpv4Dst_Choice_value {
			return nil, fmt.Errorf("simple MPLS does not handle non-explicit destination IP, got: %s", dstT)
		}
		if srcT := ip4.GetIpv4().GetSrc().GetChoice(); srcT != otg.PatternFlowIpv4Src_Choice_value {
			return nil, fmt.Errorf("simple MPLS does not handle non-explicit src IP, got: %s", srcT)
		}

		srcIP := net.ParseIP(ip4.GetIpv4().GetSrc().GetValue())
		if srcIP == nil {
			return nil, fmt.Errorf("error parsing source IPv4 address, got: %s", ip4.GetIpv4().GetSrc().GetValue())
		}
		dstIP := net.ParseIP(ip4.GetIpv4().GetDst().GetValue())
		if dstIP == nil {
			return nil, fmt.Errorf("error parsing destination IPv4 address, got: %s", ip4.GetIpv4().GetDst().GetValue())
		}

		if vv, vT := ip4.GetIpv4().GetVersion().GetValue(), ip4.GetIpv4().GetVersion().GetChoice(); vT != otg.PatternFlowIpv4Version_Choice_value || vv != 4 {
			return nil, fmt.Errorf("error parsing IP version, got type: %s, got: %d", vT, vv)
		}

		pktLayers = append(pktLayers, &layers.IPv4{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			Version: 4,
		})
	}

	// Build a packet payload consisting of 64-bytes to ensure that we have a
	// valid packet.
	//
	// TODO(robjs): In the future, this could be read from the OTG flow input.
	pl := make([]byte, 64)
	if _, err := rand.Read(pl); err != nil {
		return nil, fmt.Errorf("cannot generate random packet payload, %v", err)
	}
	pktLayers = append(pktLayers, gopacket.Payload(pl))

	return pktLayers, nil
}

// New returns a new MPLS flow generator, consisting of:
//   - a FlowGeneratorFn that is used in lwotg to create the MPLS flow.
//   - a gnmit.Task that is used to write telemetry.
func New() (lwotg.FlowGeneratorFn, gnmit.Task, error) {
	// TODO(robjs): We need a flow counter for each individual flow. This
	// implementation results in just one flow being supported currently.
	f := newFlowCounters()
	// t is a gnmit Task which reads from the gnmi channel specified and writes
	// into the cache.
	t := gnmit.Task{
		Run: func(_ gnmit.Queue, updateFn gnmit.UpdateFn, target string, cleanup func()) error {
			ticker := time.NewTicker(1 * time.Second)
			go func() {
				// TODO(robjs): Check with wenbli how gnmit tasks are supposed to be told
				// to exit.
				defer cleanup()
				for {
					<-ticker.C
					for _, u := range f.telemetry(target) {
						klog.Infof("sending telemetry update %s", u)
						updateFn(u)
					}
				}
			}()
			return nil
		},
	}

	handler := func(flow *otg.Flow, intfs []*lwotg.OTGIntf) (lwotg.TXRXFn, bool, error) {
		hdrs, err := headers(flow)
		if err != nil {
			return nil, false, err
		}

		f.Headers = hdrs

		pps, err := common.Rate(flow, hdrs)
		if err != nil {
			return nil, false, fmt.Errorf("cannot calculate rate, %v", err)
		}

		tx, rx, err := common.Ports(flow, intfs)
		if err != nil {
			return nil, false, fmt.Errorf("cannot determine ports, %v", err)
		}

		f.Name = &val{s: flow.Name, ts: flowTimeFn()}
		klog.Infof("generating flow %s: tx: %s, rx: %s, rate: %d pps", flow.GetName(), tx, rx, pps)

		genFunc := func(stop chan struct{}) {
			klog.Infof("MPLSFlowHandler send function started.")

			buf := gopacket.NewSerializeBuffer()
			gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}, hdrs...)
			size := len(buf.Bytes())

			klog.Infof("MPLSFlowHandler Tx interface %s", tx)
			handle, err := pcap.OpenLive(tx, 1500, true, pcapTimeout)
			if err != nil {
				klog.Errorf("MPLSFlowHandler Tx error: %v", err)
				return
			}
			defer handle.Close()

			f.setTransmit(true)
			for {
				select {
				case <-stop:
					klog.Infof("MPLSFlowHandler send exiting on %s", tx)
					f.setTransmit(false)
					return
				default:
					klog.Infof("MPLSFlowHandler sending %d packets", pps)
					for i := 1; i <= int(pps); i++ {
						if err := handle.WritePacketData(buf.Bytes()); err != nil {
							klog.Errorf("MPLSFlowHandler cannot write packet on interface %s, %v", tx, err)
							return
						}
					}

					f.updateTx(int(pps), size)
					// TODO(robjs): This assumes that sending the packets take zero time. We should consider being more accurate here.
					time.Sleep(1 * time.Second)
				}
			}
		}

		recvFunc := func(stop chan struct{}) {
			klog.Infof("MPLSFlowHandler receive function started on interface %s", rx)
			ih, err := pcap.NewInactiveHandle(rx)
			if err != nil {
				klog.Errorf("cannot create handle, err: %v", err)
				return
			}
			defer ih.CleanUp()
			if err := ih.SetImmediateMode(true); err != nil {
				klog.Errorf("cannot set immediate mode on handle, err: %v", err)
				return
			}

			if err := ih.SetPromisc(true); err != nil {
				klog.Errorf("cannot set promiscous mode, err: %v", err)
				return
			}

			if err := ih.SetSnapLen(packetBytes); err != nil {
				klog.Errorf("cannot set packet length, err: %v", err)
			}

			handle, err := ih.Activate()
			if err != nil {
				klog.Errorf("MPLSFlowHandler Rx error: %v", err)
				return
			}
			defer handle.Close()

			ps := gopacket.NewPacketSource(handle, handle.LinkType())
			packetCh := ps.Packets()
			for {
				select {
				case <-stop:
					// TODO(robjs): zero the flow statistics/delete the flow
					klog.Infof("MPLSFlowHandler Rx exiting on %s", rx)
					return
				case p := <-packetCh:
					if err := rxPacket(f, hdrs, p); err != nil {
						klog.Errorf("MPLSFlowHandler cannot receive packet on interface %s, %v", rx, err)
						return
					}
				}
			}
		}

		return func(tx, rx *lwotg.FlowController) {
			go genFunc(tx.Stop)
			go recvFunc(rx.Stop)
		}, true, nil
	}

	return handler, t, nil
}

// flowCounters is an internal data store for parameters that are sent as part of the
// OTG telemetry for the flow.
type flowCounters struct {
	// Name is the name of the flow.
	Name *val

	// Headers is the set of headers expected for packets matching this flow.
	Headers []gopacket.SerializableLayer

	// tx and rx store the counters for statistics relating to the flow.
	Tx, Rx *stats

	mu sync.RWMutex
	// transmit indicates whether the flow is currently transmitting.
	Transmit *val

	// tsMu protects the Timeseries map.
	tsMu sync.RWMutex
	// Timeseries maps a unix timestamp (in seconds) to an integer number of packets
	// received in that interval for rate calculation.
	Timeseries map[int64]int
}

var (
	// unixTS returns the current time in nanoseconds since the unix epoch.
	unixTS = func() int64 { return time.Now().UnixNano() }
	// flowTimeFn is a function that can be overloaded that specifies how the timestamp
	// is retrieved.
	flowTimeFn = unixTS
)

// newFlowCounters returns an empty set of counters for a specific flow.
func newFlowCounters() *flowCounters {
	return &flowCounters{
		Tx: &stats{},
		Rx: &stats{},
	}
}

// updateTx updates the transmit counters for the flow according to the specified
// packets per second rate and packet size.
func (f *flowCounters) updateTx(pps, size int) {
	f.Tx.mu.Lock()
	defer f.Tx.mu.Unlock()

	now := flowTimeFn()

	f.Tx.Rate = &val{ts: now, f: float32(pps)}

	if f.Tx.Octets == nil {
		f.Tx.Octets = &val{}
	}
	f.Tx.Octets.u += uint64(pps) * uint64(size)
	f.Tx.Octets.ts = now

	if f.Tx.Pkts == nil {
		f.Tx.Pkts = &val{}
	}
	f.Tx.Pkts.u += uint64(pps)
	f.Tx.Pkts.ts = now
}

// updateRx updates counters for received packets. It is to be called for each
// received packet with the timestamp of the arrival, and the packet size.
// In addition to updating the stats, it records a timeseries of received packets
// to allow for rate calculation.
func (f *flowCounters) updateRx(ts time.Time, size int) {
	f.tsMu.Lock()
	defer f.tsMu.Unlock()
	if f.Timeseries == nil {
		f.Timeseries = map[int64]int{}
	}
	f.Timeseries[ts.Unix()] += size

	if f.Rx.Octets == nil {
		f.Rx.Octets = &val{}
	}
	f.Rx.Octets.u += uint64(size)
	f.Rx.Octets.ts = ts.UnixNano()

	if f.Rx.Pkts == nil {
		f.Rx.Pkts = &val{}
	}
	f.Rx.Pkts.u += 1
	f.Rx.Pkts.ts = ts.UnixNano()
}

func (f *flowCounters) setTransmit(state bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Transmit == nil {
		f.Transmit = &val{}
	}
	f.Transmit.b = state
	f.Transmit.ts = time.Now().UnixNano()
}

func (f *flowCounters) clearStats() {
	f.Tx.mu.Lock()
	defer f.Tx.mu.Unlock()

	f.Rx.mu.Lock()
	defer f.Rx.mu.Unlock()

	f.Tx = &stats{}
	f.Rx = &stats{}
}

// lossPct calculates the percentage loss that the flow has experienced.
func (f *flowCounters) lossPct() float32 {
	f.Tx.mu.Lock()
	defer f.Tx.mu.Unlock()

	f.Rx.mu.Lock()
	defer f.Rx.mu.Unlock()

	return float32(f.Tx.Pkts.u-f.Rx.Pkts.u) / float32(f.Tx.Pkts.u) * 100.0
}

const (
	// slidingWindow specifies the number of seconds over which to calculate the rate
	// of the flow.
	slidingWindow int = 5
)

// currentRate calculates the current received rate based on the sliding window
// size specified. It returns the rate it bits per second.
func (f *flowCounters) rxRate() float32 {
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

// telemetry generates the set of gNMI Notifications that describes the flow's current state.
// The target argument specifies the Target value that should be included in the notifications.
func (f *flowCounters) telemetry(target string) []*gpb.Notification {
	type datapoint struct {
		d  *otgyang.Device
		ts int64
	}

	// Cannot generate statistics until the flow is initialised with a name.
	if f.Name == nil {
		return nil
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
			l.GetOrCreateFlow(name).LossPct = float32ToBinary(f.lossPct())
			upd = append(upd, &datapoint{d: l, ts: flowTimeFn()})
		}
	}

	if f.Tx != nil {
		f.Tx.mu.RLock()
		if f.Tx.Octets != nil {
			// TX statistics
			txo := &otgyang.Device{}
			txo.GetOrCreateFlow(name).GetOrCreateCounters().OutOctets = ygot.Uint64(f.Tx.Octets.u)
			upd = append(upd, &datapoint{d: txo, ts: f.Tx.Octets.ts})
		}

		if f.Tx.Pkts != nil {
			tp := &otgyang.Device{}
			tp.GetOrCreateFlow(name).GetOrCreateCounters().OutPkts = ygot.Uint64(f.Tx.Pkts.u)
			upd = append(upd, &datapoint{d: tp, ts: f.Tx.Pkts.ts})
		}

		if f.Tx.Rate != nil {
			tr := &otgyang.Device{}
			tr.GetOrCreateFlow(name).OutRate = float32ToBinary(f.Tx.Rate.f)
			upd = append(upd, &datapoint{d: tr, ts: f.Tx.Rate.ts})
		}
		f.Tx.mu.RUnlock()
	}

	if f.Rx != nil {
		// RX statistics
		f.Rx.mu.RLock()

		if f.Rx.Octets != nil {
			r := &otgyang.Device{}
			r.GetOrCreateFlow(name).GetOrCreateCounters().InOctets = ygot.Uint64(f.Rx.Octets.u)
			upd = append(upd, &datapoint{d: r, ts: f.Rx.Octets.ts})
		}

		if f.Rx.Pkts != nil {
			rp := &otgyang.Device{}
			rp.GetOrCreateFlow(name).GetOrCreateCounters().InPkts = ygot.Uint64(f.Rx.Pkts.u)
			upd = append(upd, &datapoint{d: rp, ts: f.Rx.Pkts.ts})
		}
		f.Rx.mu.RUnlock()

		rr := &otgyang.Device{}
		rr.GetOrCreateFlow(name).InRate = float32ToBinary(f.rxRate()) // express in bits per second rather than bytes
		upd = append(upd, &datapoint{d: rr, ts: flowTimeFn()})
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

// stats stores metrics that are tracked for an individual flow direction.
type stats struct {
	mu sync.RWMutex
	// rate indicates the rate at which packets are being sent or received according
	// to the specific context.
	Rate *val
	// octets indicates the total number of octets that have been sent.
	Octets *val
	// pkts indicates the total number of packets that have been sent.
	Pkts *val
}

// val is used to store a timestamped telemetry value.
type val struct {
	// ts is the timestamp in nanoseconds since the unix epoch that the value was
	// collected.
	ts int64
	// f is the value if it is of type float32.
	f float32
	// u is the value if it is of type uint64.
	u uint64
	// b is the value if it is of type bool.
	b bool
	// s is the value if it is of type string.
	s string
}

var (
	// timeFn is a function that returns a time.Time that can be overloaded in unit tests.
	timeFn = time.Now
)

// rxPacket is called for each packet that is received. It takes arguments of the statitics
// tracking the flow, the set of headers that are expected, and the received packet.
func rxPacket(f *flowCounters, hdrs []gopacket.SerializableLayer, p gopacket.Packet) error {
	match := packetInFlow(hdrs, p)
	klog.Infof("MPLS flow: packet %s -> match? %v", p, match)
	if !match {
		return nil
	}
	klog.Infof("MPLS flow: received packet with size %d", len(p.Data()))

	f.updateRx(timeFn(), len(p.Data()))
	return nil
}

// packetInFlow checks whether the packet p matches the specification in hdrs by checking
// the inner IPv4 header in p matches the inner IP header in hdrs. The values of other
// headers are not checked.
func packetInFlow(hdrs []gopacket.SerializableLayer, p gopacket.Packet) bool {
	if len(hdrs) < 2 {
		return false
	}

	innerSpec := hdrs[len(hdrs)-2] // choose the IPv4 header
	recv := p.Layer(layers.LayerTypeIPv4)
	recvIP4, recvOK := recv.(*layers.IPv4)
	spec, specOK := innerSpec.(*layers.IPv4)
	if !specOK || !recvOK {
		klog.Errorf("did not find IPv4 headers, specOK: %v, recvOK: %v", specOK, recvOK)
		return false
	}
	klog.Infof("received IPv4 header is %v", recv)
	return recvIP4.SrcIP.Equal(spec.SrcIP) && recvIP4.DstIP.Equal(spec.DstIP)
}
