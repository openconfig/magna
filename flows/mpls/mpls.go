// Package mpls parses OTG flow descriptions that consist of
// MPLS packets and returns functions that can generate and receive
// packets for these flows. These can be used with the LWOTG
// implementation.
package mpls

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"github.com/openconfig/lemming/gnmi/gnmit"
	"github.com/openconfig/magna/flows/common"
	"github.com/openconfig/magna/lwotg"
	"k8s.io/klog"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

var (
	// timeout specifies how long to wait for a PCAP handle.
	pcapTimeout = 30 * time.Second
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

	return pktLayers, nil
}

// New returns a new MPLS flow generator, consisting of:
//   - a FlowGeneratorFn that is used in lwotg to create the MPLS flow.
//   - a gnmit.Task that is used to write telemetry.
func New() (lwotg.FlowGeneratorFn, gnmit.Task, error) {
	gnmiCh := make(chan *gpb.Notification, 10)

	// t is a gnmit Task which reads from the gnmi channel specified and writes
	// into the cache.
	t := gnmit.Task{
		Run: func(_ gnmit.Queue, updateFn gnmit.UpdateFn, target string, cleanup func()) error {
			go func() {
				// TODO(robjs): Check with wenbli how gnmit tasks are supposed to be told
				// to exit.
				defer cleanup()
				for {
					updateFn(<-gnmiCh)
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

		pps, err := common.Rate(flow, hdrs)
		if err != nil {
			return nil, false, fmt.Errorf("cannot calculate rate, %v", err)
		}

		tx, rx, err := common.Ports(flow, intfs)
		if err != nil {
			return nil, false, fmt.Errorf("cannot determine ports, %v", err)
		}

		klog.Infof("generating flow %s: tx: %s, rx: %s, rate: %d pps", flow.GetName(), tx, rx, pps)

		genFunc := func(stop chan struct{}) {
			klog.Infof("MPLSFlowHandler send function started.")

			buf := gopacket.NewSerializeBuffer()
			gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, hdrs...)

			klog.Infof("MPLSFlowHandler Tx interface %s", tx)
			handle, err := pcap.OpenLive(tx, 9000, true, pcapTimeout)
			if err != nil {
				klog.Errorf("MPLSFlowHandler Tx error: %v", err)
				return
			}
			defer handle.Close()

			for {
				select {
				case <-stop:
					klog.Infof("MPLSFlowHandler send exiting on %s", tx)
					return
				default:
					klog.Infof("MPLSFlowHandler sending %d packets", pps)
					for i := 1; i <= int(pps); i++ {
						if err := handle.WritePacketData(buf.Bytes()); err != nil {
							klog.Errorf("MPLSFlowHandler cannot write packet on interface %s, %v", tx, err)
							return
						}
					}
					// TODO(robjs): This assumes that sending the packets take zero time. We should consider being more accurate here.
					time.Sleep(1 * time.Second)
				}
			}
		}

		recvFunc := func(stop chan struct{}) {
			klog.Infof("MPLSFlowHandler receive function started on interface %s", rx)
			handle, err := pcap.OpenLive(rx, 9000, true, pcapTimeout)
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
					klog.Infof("MPLSFlowHandler Rx exiting on %s", rx)
					return
				case p := <-packetCh:
					upd, err := rxPacket(p)
					if err != nil {
						klog.Errorf("MPLSFlowHandler cannot receive packet on interface %s, %v", rx, err)
						return
					}
					gnmiCh <- upd
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

// rxPacket is called for each packet that is received.
func rxPacket(p gopacket.Packet) (*gpb.Notification, error) {
	klog.Infof("received packet %v", p)
	return nil, nil
}
