package ip

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"google.golang.org/protobuf/proto"
)

var (
	v4Choice       = otg.FlowHeader_Choice_ipv4
	v6Choice       = otg.FlowHeader_Choice_ipv6
	mplsChoice     = otg.FlowHeader_Choice_mpls
	ethernetChoice = otg.FlowHeader_Choice_ethernet

	dstMACValue  = otg.PatternFlowEthernetDst_Choice_value
	dstMACValues = otg.PatternFlowEthernetDst_Choice_values

	srcMACValue  = otg.PatternFlowEthernetSrc_Choice_value
	srcMACValues = otg.PatternFlowEthernetSrc_Choice_values

	dstIPValue      = otg.PatternFlowIpv4Dst_Choice_value
	dstIPv6Value    = otg.PatternFlowIpv6Dst_Choice_value
	srcIPValue      = otg.PatternFlowIpv4Src_Choice_value
	srcIPv6Value    = otg.PatternFlowIpv6Src_Choice_value
	ip4VersionValue = otg.PatternFlowIpv4Version_Choice_value
	ip6VersionValue = otg.PatternFlowIpv6Version_Choice_value
)

func TestHeaders(t *testing.T) {
	validMAC, err := net.ParseMAC("00:01:02:03:04:05")
	if err != nil {
		t.Fatalf("cannot parse MAC, %v", err)
	}

	tests := []struct {
		desc       string
		inFlow     *otg.Flow
		wantLayers []gopacket.SerializableLayer
		wantErr    bool
	}{
		{
			desc:    "no layers",
			inFlow:  &otg.Flow{},
			wantErr: true,
		},
		{
			desc: "non-ethernet or ip layer",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{{
					Choice: &mplsChoice,
				}},
			},
			wantErr: true,
		},
		{
			desc: "multiple ethernet layers",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{{
					Choice: &ethernetChoice,
				}, {
					Choice: &mplsChoice,
				}, {
					Choice: &ethernetChoice,
				}},
			},
			wantErr: true,
		},
		{
			desc: "invalid destination MAC type",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{{
					Choice: &ethernetChoice,
					Ethernet: &otg.FlowEthernet{
						Dst: &otg.PatternFlowEthernetDst{
							Choice: &dstMACValues,
						},
					},
				}},
			},
			wantErr: true,
		},
		{
			desc: "invalid source MAC type",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{{
					Choice: &ethernetChoice,
					Ethernet: &otg.FlowEthernet{
						Src: &otg.PatternFlowEthernetSrc{
							Choice: &srcMACValues,
						},
					},
				}},
			},
			wantErr: true,
		},
		{
			desc: "valid MACs",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{{
					Choice: &ethernetChoice,
					Ethernet: &otg.FlowEthernet{
						Dst: &otg.PatternFlowEthernetDst{
							Choice: &dstMACValue,
							Value:  proto.String("00:01:02:03:04:05"),
						},
						Src: &otg.PatternFlowEthernetSrc{
							Choice: &srcMACValue,
							Value:  proto.String("00:01:02:03:04:05"),
						},
					},
				}},
			},
			wantLayers: []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       validMAC,
					DstMAC:       validMAC,
					EthernetType: layers.EthernetTypeMPLSUnicast,
				},
			},
		},
		{
			desc: "invalid destination MAC",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{{
					Choice: &ethernetChoice,
					Ethernet: &otg.FlowEthernet{
						Dst: &otg.PatternFlowEthernetDst{
							Choice: &dstMACValue,
							Value:  proto.String("not-a-mac"),
						},
						Src: &otg.PatternFlowEthernetSrc{
							Choice: &srcMACValue,
							Value:  proto.String("00:01:02:03:04:05"),
						},
					},
				}},
			},
			wantErr: true,
		}, {
			desc: "invalid source MAC",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{{
					Choice: &ethernetChoice,
					Ethernet: &otg.FlowEthernet{
						Dst: &otg.PatternFlowEthernetDst{
							Choice: &dstMACValue,
							Value:  proto.String("00:01:02:03:04:05"),
						},
						Src: &otg.PatternFlowEthernetSrc{
							Choice: &srcMACValue,
							Value:  proto.String("not-a-mac"),
						},
					},
				}},
			},
			wantErr: true,
		},
		{
			desc: "single ipv4 header",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{
					{
						Choice: &ethernetChoice,
						Ethernet: &otg.FlowEthernet{
							Dst: &otg.PatternFlowEthernetDst{
								Choice: &dstMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
							Src: &otg.PatternFlowEthernetSrc{
								Choice: &srcMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
						},
					},
					{
						Choice: &v4Choice,
						Ipv4: &otg.FlowIpv4{
							Version: &otg.PatternFlowIpv4Version{
								Choice: &ip4VersionValue,
								Value:  proto.Uint32(4),
							},
							Src: &otg.PatternFlowIpv4Src{
								Choice: &srcIPValue,
								Value:  proto.String("1.1.1.1"),
							},
							Dst: &otg.PatternFlowIpv4Dst{
								Choice: &dstIPValue,
								Value:  proto.String("1.1.1.2"),
							},
						},
					},
				},
			},
			wantLayers: []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       validMAC,
					DstMAC:       validMAC,
					EthernetType: layers.EthernetTypeIPv4,
				},
				&layers.IPv4{
					Version: 4,
					SrcIP:   net.ParseIP("1.1.1.1"),
					DstIP:   net.ParseIP("1.1.1.2"),
				},
			},
		},
		{
			desc: "single ipv6 header",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{
					{
						Choice: &ethernetChoice,
						Ethernet: &otg.FlowEthernet{
							Dst: &otg.PatternFlowEthernetDst{
								Choice: &dstMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
							Src: &otg.PatternFlowEthernetSrc{
								Choice: &srcMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
						},
					},
					{
						Choice: &v6Choice,
						Ipv6: &otg.FlowIpv6{
							Version: &otg.PatternFlowIpv6Version{
								Choice: &ip6VersionValue,
								Value:  proto.Uint32(6),
							},
							Src: &otg.PatternFlowIpv6Src{
								Choice: &srcIPv6Value,
								Value:  proto.String("::1"),
							},
							Dst: &otg.PatternFlowIpv6Dst{
								Choice: &dstIPv6Value,
								Value:  proto.String("::2"),
							},
						},
					},
				},
			},
			wantLayers: []gopacket.SerializableLayer{
				&layers.Ethernet{
					SrcMAC:       validMAC,
					DstMAC:       validMAC,
					EthernetType: layers.EthernetTypeIPv6,
				},
				&layers.IPv6{
					Version: 6,
					SrcIP:   net.ParseIP("::1"),
					DstIP:   net.ParseIP("::2"),
				},
			},
		},
		{
			desc: "multiple ipv4 headers - invalid",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{
					{
						Choice: &ethernetChoice,
						Ethernet: &otg.FlowEthernet{
							Dst: &otg.PatternFlowEthernetDst{
								Choice: &dstMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
							Src: &otg.PatternFlowEthernetSrc{
								Choice: &srcMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
						},
					},
					{
						Choice: &v4Choice,
						Ipv4: &otg.FlowIpv4{
							Version: &otg.PatternFlowIpv4Version{
								Choice: &ip4VersionValue,
								Value:  proto.Uint32(4),
							},
							Src: &otg.PatternFlowIpv4Src{
								Choice: &srcIPValue,
								Value:  proto.String("1.1.1.1"),
							},
							Dst: &otg.PatternFlowIpv4Dst{
								Choice: &dstIPValue,
								Value:  proto.String("1.1.1.2"),
							},
						},
					},
					{
						Choice: &v4Choice,
						Ipv4: &otg.FlowIpv4{
							Version: &otg.PatternFlowIpv4Version{
								Choice: &ip4VersionValue,
								Value:  proto.Uint32(4),
							},
							Src: &otg.PatternFlowIpv4Src{
								Choice: &srcIPValue,
								Value:  proto.String("1.1.1.1"),
							},
							Dst: &otg.PatternFlowIpv4Dst{
								Choice: &dstIPValue,
								Value:  proto.String("1.1.1.2"),
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "multiple ipv6 headers - invalid",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{
					{
						Choice: &ethernetChoice,
						Ethernet: &otg.FlowEthernet{
							Dst: &otg.PatternFlowEthernetDst{
								Choice: &dstMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
							Src: &otg.PatternFlowEthernetSrc{
								Choice: &srcMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
						},
					},
					{
						Choice: &v6Choice,
						Ipv6: &otg.FlowIpv6{
							Version: &otg.PatternFlowIpv6Version{
								Choice: &ip6VersionValue,
								Value:  proto.Uint32(6),
							},
							Src: &otg.PatternFlowIpv6Src{
								Choice: &srcIPv6Value,
								Value:  proto.String("::1"),
							},
							Dst: &otg.PatternFlowIpv6Dst{
								Choice: &dstIPv6Value,
								Value:  proto.String("::2"),
							},
						},
					},
					{
						Choice: &v6Choice,
						Ipv6: &otg.FlowIpv6{
							Version: &otg.PatternFlowIpv6Version{
								Choice: &ip6VersionValue,
								Value:  proto.Uint32(6),
							},
							Src: &otg.PatternFlowIpv6Src{
								Choice: &srcIPv6Value,
								Value:  proto.String("::1"),
							},
							Dst: &otg.PatternFlowIpv6Dst{
								Choice: &dstIPv6Value,
								Value:  proto.String("::2"),
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "ipv4 in ipv6 - invalid",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{
					{
						Choice: &ethernetChoice,
						Ethernet: &otg.FlowEthernet{
							Dst: &otg.PatternFlowEthernetDst{
								Choice: &dstMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
							Src: &otg.PatternFlowEthernetSrc{
								Choice: &srcMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
						},
					},
					{
						Choice: &v6Choice,
						Ipv6: &otg.FlowIpv6{
							Version: &otg.PatternFlowIpv6Version{
								Choice: &ip6VersionValue,
								Value:  proto.Uint32(6),
							},
							Src: &otg.PatternFlowIpv6Src{
								Choice: &srcIPv6Value,
								Value:  proto.String("::1"),
							},
							Dst: &otg.PatternFlowIpv6Dst{
								Choice: &dstIPv6Value,
								Value:  proto.String("::2"),
							},
						},
					},
					{
						Choice: &v4Choice,
						Ipv4: &otg.FlowIpv4{
							Version: &otg.PatternFlowIpv4Version{
								Choice: &ip4VersionValue,
								Value:  proto.Uint32(4),
							},
							Src: &otg.PatternFlowIpv4Src{
								Choice: &srcIPValue,
								Value:  proto.String("1.1.1.1"),
							},
							Dst: &otg.PatternFlowIpv4Dst{
								Choice: &dstIPValue,
								Value:  proto.String("1.1.1.2"),
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "ipv6 in ipv4 - invalid",
			inFlow: &otg.Flow{
				Packet: []*otg.FlowHeader{
					{
						Choice: &ethernetChoice,
						Ethernet: &otg.FlowEthernet{
							Dst: &otg.PatternFlowEthernetDst{
								Choice: &dstMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
							Src: &otg.PatternFlowEthernetSrc{
								Choice: &srcMACValue,
								Value:  proto.String("00:01:02:03:04:05"),
							},
						},
					},
					{
						Choice: &v4Choice,
						Ipv4: &otg.FlowIpv4{
							Version: &otg.PatternFlowIpv4Version{
								Choice: &ip4VersionValue,
								Value:  proto.Uint32(4),
							},
							Src: &otg.PatternFlowIpv4Src{
								Choice: &srcIPValue,
								Value:  proto.String("1.1.1.1"),
							},
							Dst: &otg.PatternFlowIpv4Dst{
								Choice: &dstIPValue,
								Value:  proto.String("1.1.1.2"),
							},
						},
					},
					{
						Choice: &v6Choice,
						Ipv6: &otg.FlowIpv6{
							Version: &otg.PatternFlowIpv6Version{
								Choice: &ip6VersionValue,
								Value:  proto.Uint32(6),
							},
							Src: &otg.PatternFlowIpv6Src{
								Choice: &srcIPv6Value,
								Value:  proto.String("::1"),
							},
							Dst: &otg.PatternFlowIpv6Dst{
								Choice: &dstIPv6Value,
								Value:  proto.String("::2"),
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := headers(tt.inFlow)
			if (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error, got: %v, wantErr? %v", err, tt.wantErr)
			}

			if len(got) < 2 {
				return
			}
			// Skip the 64-byte random payload.
			if diff := cmp.Diff(got[0:len(got)-1], tt.wantLayers, cmpopts.EquateEmpty(), cmpopts.IgnoreUnexported(layers.IPv6{})); diff != "" {
				t.Fatalf("did not get expected layers, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

func TestBPFFilter(t *testing.T) {
	tests := []struct {
		desc       string
		inHeaders  []gopacket.SerializableLayer
		wantFilter string
		wantErr    bool
	}{{
		desc: "invalid number of layers",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		},
		wantErr: true,
	}, {
		desc: "ipv4",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			&layers.IPv4{
				Version: 4,
				SrcIP:   net.ParseIP("192.0.2.1"),
				DstIP:   net.ParseIP("192.0.2.2"),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		},
		wantFilter: "ip src host 192.0.2.1 and ip dst host 192.0.2.2",
	}, {
		desc: "ipv6",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			&layers.IPv6{
				Version: 6,
				SrcIP:   net.ParseIP("2001:db8::1"),
				DstIP:   net.ParseIP("2001:db8::2"),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		},
		wantFilter: "ip6 src host 2001:db8::1 and ip6 dst host 2001:db8::2",
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := bpfFilter(tt.inHeaders)
			if (err != nil) != tt.wantErr {
				t.Fatalf("bpfFilter(%v): did not get expected err, got: %v, wantErr? %v", tt.inHeaders, err, tt.wantErr)
			}

			if got != tt.wantFilter {
				t.Fatalf(`bpfFilter(%v): did not get expected filter, got: "%s", want: "%s"`, tt.inHeaders, got, tt.wantFilter)
			}
		})
	}
}

func TestPacketInFlow(t *testing.T) {

	mac, err := net.ParseMAC("16:61:ee:09:bc:dc")
	if err != nil {
		t.Fatalf("cannot parse MAC, %v", err)
	}

	simplePacket := []gopacket.SerializableLayer{
		&layers.Ethernet{
			SrcMAC:       mac,
			DstMAC:       mac,
			EthernetType: layers.EthernetTypeMPLSUnicast,
		},
		&layers.MPLS{
			Label:       42,
			TTL:         100,
			StackBottom: true,
		},
		&layers.IPv4{
			Version: 4,
			SrcIP:   net.ParseIP("1.1.1.1"),
			DstIP:   net.ParseIP("2.2.2.2"),
		},
	}

	stackedPacket := []gopacket.SerializableLayer{
		&layers.Ethernet{
			SrcMAC:       mac,
			DstMAC:       mac,
			EthernetType: layers.EthernetTypeMPLSUnicast,
		},
		&layers.MPLS{
			Label:       42,
			TTL:         100,
			StackBottom: false,
		},
		&layers.MPLS{
			Label:       44,
			TTL:         200,
			StackBottom: true,
		},
		&layers.IPv4{
			Version: 4,
			SrcIP:   net.ParseIP("1.2.3.4"),
			DstIP:   net.ParseIP("2.3.4.5"),
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	gopacket.SerializeLayers(buf, opts, simplePacket...)
	simplePkt := buf.Bytes()
	inSimple := gopacket.NewPacket(simplePkt, layers.LinkTypeEthernet, gopacket.Default)

	gopacket.SerializeLayers(buf, opts, stackedPacket...)
	stackedPkt := buf.Bytes()
	inStacked := gopacket.NewPacket(stackedPkt, layers.LinkTypeEthernet, gopacket.Default)

	tests := []struct {
		desc      string
		inHeaders []gopacket.SerializableLayer
		inPacket  gopacket.Packet
		want      bool
		wantErr   bool
	}{{
		desc: "not in flow, not enough headers in spec",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{
				SrcMAC: mac,
				DstMAC: mac,
			},
		},
		inPacket: inSimple,
		want:     false,
	}, {
		desc: "not in flow, no ipv4 header in spec",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			&layers.MPLS{},
			&layers.MPLS{},
		},
		inPacket: inSimple,
		want:     false,
	}, {
		desc: "in flow, matching ipv4 header",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			&layers.MPLS{},
			&layers.IPv4{
				Version: 4,
				SrcIP:   net.ParseIP("1.1.1.1"),
				DstIP:   net.ParseIP("2.2.2.2"),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		},
		inPacket: inSimple,
		want:     true,
	}, {
		desc: "not in flow, no matching ipv4 header",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			&layers.MPLS{},
			&layers.IPv4{
				Version: 4,
				SrcIP:   net.ParseIP("1.1.1.1"),
				DstIP:   net.ParseIP("100.100.100.100"),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		},
		inPacket: inSimple,
		want:     false,
	}, {
		desc: "in flow, stacked packet",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			&layers.MPLS{},
			&layers.MPLS{},
			&layers.MPLS{},
			&layers.IPv4{
				Version: 4,
				SrcIP:   net.ParseIP("1.2.3.4"),
				DstIP:   net.ParseIP("2.3.4.5"),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		},
		inPacket: inStacked,
		want:     true,
	}, {
		desc: "not in flow, stacked packet",
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			&layers.MPLS{},
			&layers.MPLS{},
			&layers.MPLS{},
			&layers.IPv4{
				Version: 4,
				SrcIP:   net.ParseIP("1.2.3.4"),
				DstIP:   net.ParseIP("1.2.3.5"),
			},
			gopacket.Payload([]byte{1, 2, 3, 4}),
		},
		inPacket: inStacked,
		want:     false,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := packetInFlow(tt.inHeaders, tt.inPacket)
			if got != tt.want {
				t.Fatalf("packetInFlow(hdrs, packet): didn't get expected result, got: %v, want: %v", got, tt.want)
			}
		})
	}
}
