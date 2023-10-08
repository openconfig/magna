package ip

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"github.com/openconfig/magna/flows/common"
	"github.com/openconfig/magna/lwotg"
	"github.com/openconfig/magna/lwotgtelem/gnmit"
	"k8s.io/klog"
)

// New returns a new IP flow generator, consisting of:
//   - a FlowGeneratorFn that is used in lwotg to create the IP flow.
//   - a gnmit.Task that is used to write telemetry.
func New() (lwotg.FlowGeneratorFn, gnmit.Task, error) {

	// reporter encapsulates the counters for multiple flows. The IP flow handler
	// is created once at startup time of the magna instance.
	reporter := common.NewReporter()

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
					reporter.Telemetry(updateFn, target)
				}
			}()
			return nil
		},
	}

	return common.Handler(headers, packetInFlow, reporter), t, nil
}

func headers(f *otg.Flow) ([]gopacket.SerializableLayer, error) {
	var (
		ethernet *otg.FlowHeader
		ip4      *otg.FlowHeader
		ip6      *otg.FlowHeader
	)

	for _, layer := range f.Packet {
		switch t := layer.GetChoice(); t {
		case otg.FlowHeader_Choice_ethernet:
			if ethernet != nil {
				return nil, fmt.Errorf("multiple Ethernet layers not handled by IP plugin")
			}
			ethernet = layer
		case otg.FlowHeader_Choice_ipv4:
			if ip4 != nil {
				return nil, fmt.Errorf("multiple IPv4, or outer IPv4 layers not handled by IP plugin")
			}
			if ip6 != nil {
				return nil, fmt.Errorf("IPv6 in IPv4 not handled by IP plugin")
			}
			ip4 = layer
		case otg.FlowHeader_Choice_ipv6:
			if ip6 != nil {
				return nil, fmt.Errorf("multiple IPv6, or outer IPv6 layers not handled by IP plugin")
			}
			if ip4 != nil {
				// TODO(alshabib): perhaps we should, but we don't now, so there.
				return nil, fmt.Errorf("IPv4 in IPv6 not handled by IP plugin")
			}
			ip6 = layer
		default:
			return nil, fmt.Errorf("IP plugin does not handle layer %s", t)
		}
	}

	if dstT := ethernet.GetEthernet().GetDst().GetChoice(); dstT != otg.PatternFlowEthernetDst_Choice_value {
		return nil, fmt.Errorf("IP does not handle non-explicit destination MAC, got: %s", dstT)
	}
	if srcT := ethernet.GetEthernet().GetSrc().GetChoice(); srcT != otg.PatternFlowEthernetSrc_Choice_value {
		return nil, fmt.Errorf("IP does not handle non-explicit src MAC, got: %v", srcT)
	}

	srcMAC, err := net.ParseMAC(ethernet.GetEthernet().GetSrc().GetValue())
	if err != nil {
		return nil, fmt.Errorf("cannot parse source MAC, %v", err)
	}
	dstMAC, err := net.ParseMAC(ethernet.GetEthernet().GetDst().GetValue())
	if err != nil {
		return nil, fmt.Errorf("cannot parse destination MAC, %v", err)
	}

	var pktLayers []gopacket.SerializableLayer

	switch {
	case ip4 != nil:
		if dstT := ip4.GetIpv4().GetDst().GetChoice(); dstT != otg.PatternFlowIpv4Dst_Choice_value {
			return nil, fmt.Errorf("IP does not handle non-explicit destination IP, got: %s", dstT)
		}
		if srcT := ip4.GetIpv4().GetSrc().GetChoice(); srcT != otg.PatternFlowIpv4Src_Choice_value {
			return nil, fmt.Errorf("IP does not handle non-explicit src IP, got: %s", srcT)
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

		pktLayers = append(pktLayers, &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
			&layers.IPv4{
				SrcIP:   srcIP,
				DstIP:   dstIP,
				Version: 4,
			})
	case ip6 != nil:
		if dstT := ip6.GetIpv6().GetDst().GetChoice(); dstT != otg.PatternFlowIpv6Dst_Choice_value {
			return nil, fmt.Errorf("IP does not handle non-explicit destination IP, got: %s", dstT)
		}
		if srcT := ip6.GetIpv6().GetSrc().GetChoice(); srcT != otg.PatternFlowIpv6Src_Choice_value {
			return nil, fmt.Errorf("IP does not handle non-explicit src IP, got: %s", srcT)
		}

		srcIP := net.ParseIP(ip6.GetIpv6().GetSrc().GetValue())
		if srcIP == nil {
			return nil, fmt.Errorf("error parsing source IPv6 address, got: %s", ip4.GetIpv6().GetSrc().GetValue())
		}
		dstIP := net.ParseIP(ip6.GetIpv6().GetDst().GetValue())
		if dstIP == nil {
			return nil, fmt.Errorf("error parsing destination IPv6 address, got: %s", ip6.GetIpv6().GetDst().GetValue())
		}

		if vv, vT := ip6.GetIpv6().GetVersion().GetValue(), ip6.GetIpv6().GetVersion().GetChoice(); vT != otg.PatternFlowIpv6Version_Choice_value || vv != 6 {
			return nil, fmt.Errorf("error parsing IP version, got type: %s, got: %d", vT, vv)
		}

		pktLayers = append(pktLayers, &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv6,
		},
			&layers.IPv6{
				SrcIP:   srcIP,
				DstIP:   dstIP,
				Version: 6,
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

// packetInFlow checks whether the packet p matches the specification in hdrs by checking
// the inner IPv4 header in p matches the inner IP header in hdrs. The values of other
// headers are not checked.
func packetInFlow(hdrs []gopacket.SerializableLayer, p gopacket.Packet) bool {
	if len(hdrs) < 2 {
		return false
	}

	innerSpec := hdrs[len(hdrs)-1] // choose the IPv4 header
	switch spec := innerSpec.(type) {
	case *layers.IPv4:
		recv := p.Layer(layers.LayerTypeIPv4)
		recvIP4, recvOK := recv.(*layers.IPv4)
		if !recvOK {
			klog.Errorf("spec is ipv4 but received packet has %+v", p.Layers())
		}
		return recvIP4.SrcIP.Equal(spec.SrcIP) && recvIP4.DstIP.Equal(spec.DstIP)
	case *layers.IPv6:
		recv := p.Layer(layers.LayerTypeIPv6)
		recvIP6, recvOK := recv.(*layers.IPv6)
		if !recvOK {
			klog.Errorf("spec is ipv6 but received packet has %+v", p.Layers())
		}
		return recvIP6.SrcIP.Equal(spec.SrcIP) && recvIP6.DstIP.Equal(spec.DstIP)

	}

	return false
}
