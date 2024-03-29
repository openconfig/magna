// Package mpls parses OTG flow descriptions that consist of
// MPLS packets and returns functions that can generate and receive
// packets for these flows. These can be used with the LWOTG
// implementation.
package mpls

import (
	"bytes"
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
	"k8s.io/klog/v2"
)

const (
	// defaultMPLSTTL is the TTL value used by default in the MPLS header.
	defaultMPLSTTL uint8 = 64
	// maxReceiveLabels is the maximum number MPLS labels that a received flow can have applied.
	// It is used when generating BPF filters for received packets where we cannot match an
	// arbitrary label depth.
	maxReceiveLabels = 20
)

// New returns a new MPLS flow generator, consisting of:
//   - a FlowGeneratorFn that is used in lwotg to create the MPLS flow.
//   - a gnmit.Task that is used to write telemetry.
func New() (lwotg.FlowGeneratorFn, gnmit.Task, error) {
	// reporter encapsulates the counters for multiple flows. The MPLS flow handler is
	// created once at startup time of the magna instance.
	reporter := common.NewReporter()

	// t is a gnmit Task which reads from the gnmi channel specified and writes
	// into the cache.
	t := gnmit.Task{
		Run: func(_ gnmit.Queue, updateFn gnmit.UpdateFn, target string, cleanup func()) error {
			// Report telemetry every 2 seconds -- this avoids us creating too much contention
			// around the statistics lock.
			//
			// TODO(robjs): Make this configurable in the future and with a minimum value that
			// allows sufficient flow scale.
			ticker := time.NewTicker(2 * time.Second)
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

	return common.Handler(headers, bpfFilter, packetInFlow, reporter), t, nil
}

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

// bpfFilter generates a BPF filter that matches this flow. It returns an error if it cannot
// build a filter.
func bpfFilter(hdrs []gopacket.SerializableLayer) (string, error) {
	if len(hdrs) < 2 {
		return "", fmt.Errorf("insufficient layers to extract IPv4 headers, got %d", len(hdrs))
	}
	ipv4Hdr, ok := hdrs[len(hdrs)-2].(*layers.IPv4)
	if !ok {
		return "", fmt.Errorf("invalid headers, penultimate layer is not IPv4, got: %T", hdrs[len(hdrs)-2])
	}

	buf := &bytes.Buffer{}

	// BPF when we use the 'mpls' keyword will set the offset to be +4b to look for the IP header, but this doesn't
	// cleanly work when we're matching arbitrary numbers of labels -- so we need to create a number of filters.
	// Primarly, we create them for MPLS packets.
	srcIPBytes := fmt.Sprintf("0x%x", []byte(ipv4Hdr.SrcIP.To4()))
	dstIPBytes := fmt.Sprintf("0x%x", []byte(ipv4Hdr.DstIP.To4()))
	buf.WriteString("(mpls and (")
	for i := 0; i < maxReceiveLabels; i++ {
		// We have:
		//	14 bytes of Ethernet header
		//	Labels * (4 bytes) of MPLS headers
		//	12 bytes of IP header minus the source and destination address
		// Thus, for an MPLS packet (0x8847 Ethertype) we need to generate a filter that checks for a source address at
		// 14+12+4 = 30 bytes offset for 1 label, and then destination address at 14+12+4+4 = 34 bytes. We increment
		// both by 4 bytes for each subsequent label.
		srcIPOffset := 30 + (i * 4)
		dstIPOffset := 30 + (i * 4) + 4
		buf.WriteString(fmt.Sprintf("(ether[%d:4] == %s and ether[%d:4] == %s)", srcIPOffset, srcIPBytes, dstIPOffset, dstIPBytes))
		if i != maxReceiveLabels-1 {
			buf.WriteString(" or ")
		}
	}
	buf.WriteString(")) or ")
	buf.WriteString(fmt.Sprintf("(ip and src host %s and dst host %s)", ipv4Hdr.SrcIP.String(), ipv4Hdr.DstIP.String()))

	filter := buf.String()
	klog.Infof("applying filter %s", filter)
	return filter, nil
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
	return recvIP4.SrcIP.Equal(spec.SrcIP) && recvIP4.DstIP.Equal(spec.DstIP)
}
