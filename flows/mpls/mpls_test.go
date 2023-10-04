package mpls

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

	mplsTTLValue    = otg.PatternFlowMplsTimeToLive_Choice_value
	mplsTTLValues   = otg.PatternFlowMplsTimeToLive_Choice_values
	mplsBOSValue    = otg.PatternFlowMplsBottomOfStack_Choice_value
	mplsBOSValues   = otg.PatternFlowMplsBottomOfStack_Choice_values
	mplsLabelValue  = otg.PatternFlowMplsLabel_Choice_value
	mplsLabelValues = otg.PatternFlowMplsLabel_Choice_values

	dstIPValue      = otg.PatternFlowIpv4Dst_Choice_value
	dstIPValues     = otg.PatternFlowIpv4Dst_Choice_values
	srcIPValue      = otg.PatternFlowIpv4Src_Choice_value
	srcIPValues     = otg.PatternFlowIpv4Src_Choice_values
	ipVersionValue  = otg.PatternFlowIpv4Version_Choice_value
	ipVersionValues = otg.PatternFlowIpv4Version_Choice_values
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
	}{{
		desc:    "no layers",
		inFlow:  &otg.Flow{},
		wantErr: true,
	}, {
		desc: "non-ethernet or mpls layer",
		inFlow: &otg.Flow{
			Packet: []*otg.FlowHeader{{
				Choice: &v6Choice,
			}},
		},
		wantErr: true,
	}, {
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
	}, {
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
	}, {
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
	}, {
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
	}, {
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
	}, {
		desc: "single MPLS header",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Uint32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Uint32(1),
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
			&layers.MPLS{
				Label:       42,
				StackBottom: true,
				TTL:         2,
			},
		},
	}, {
		desc: "invalid MPLS label type",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValues,
					},
				},
			}},
		},
		wantErr: true,
	}, {
		desc: "invalid MPLS TTL type",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValues,
					},
				},
			}},
		},
		wantErr: true,
	}, {
		desc: "invalid MPLS BOS type",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Uint32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValues,
					},
				},
			}},
		},
		wantErr: true,
	}, {
		desc: "multiple MPLS headers",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Uint32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Uint32(0),
					},
				},
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(84),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Uint32(1),
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
			&layers.MPLS{
				Label:       42,
				StackBottom: false,
				TTL:         2,
			},
			&layers.MPLS{
				Label:       84,
				StackBottom: true,
				TTL:         defaultMPLSTTL,
			},
		},
	}, {
		desc: "ipv4 in MPLS - valid",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Uint32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Uint32(1),
					},
				},
			}, {
				Choice: &v4Choice,
				Ipv4: &otg.FlowIpv4{
					Src: &otg.PatternFlowIpv4Src{
						Choice: &srcIPValue,
						Value:  proto.String("1.1.1.1"),
					},
					Dst: &otg.PatternFlowIpv4Dst{
						Choice: &dstIPValue,
						Value:  proto.String("2.2.2.2"),
					},
					Version: &otg.PatternFlowIpv4Version{
						Choice: &ipVersionValue,
						Value:  proto.Uint32(4),
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
			&layers.MPLS{
				Label:       42,
				StackBottom: true,
				TTL:         2,
			},
			&layers.IPv4{
				Version: 4,
				SrcIP:   net.ParseIP("1.1.1.1"),
				DstIP:   net.ParseIP("2.2.2.2"),
			},
		},
	}, {
		desc: "ipv4 in MPLS - invalid source type",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Uint32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Uint32(1),
					},
				},
			}, {
				Choice: &v4Choice,
				Ipv4: &otg.FlowIpv4{
					Src: &otg.PatternFlowIpv4Src{
						Choice: &srcIPValues,
					},
					Dst: &otg.PatternFlowIpv4Dst{
						Choice: &dstIPValue,
						Value:  proto.String("2.2.2.2"),
					},
					Version: &otg.PatternFlowIpv4Version{
						Choice: &ipVersionValue,
						Value:  proto.Uint32(4),
					},
				},
			}},
		},
		wantErr: true,
	}, {
		desc: "ipv4 in MPLS - invalid destination type",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Uint32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Uint32(1),
					},
				},
			}, {
				Choice: &v4Choice,
				Ipv4: &otg.FlowIpv4{
					Src: &otg.PatternFlowIpv4Src{
						Choice: &srcIPValue,
						Value:  proto.String("1.1.1.1"),
					},
					Dst: &otg.PatternFlowIpv4Dst{
						Choice: &dstIPValues,
					},
					Version: &otg.PatternFlowIpv4Version{
						Choice: &ipVersionValue,
						Value:  proto.Uint32(4),
					},
				},
			}},
		},
		wantErr: true,
	}, {
		desc: "ipv4 in MPLS - invalid version",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Uint32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Uint32(1),
					},
				},
			}, {
				Choice: &v4Choice,
				Ipv4: &otg.FlowIpv4{
					Src: &otg.PatternFlowIpv4Src{
						Choice: &srcIPValue,
						Value:  proto.String("1.1.1.1"),
					},
					Dst: &otg.PatternFlowIpv4Dst{
						Choice: &dstIPValue,
						Value:  proto.String("2.2.2.2"),
					},
					Version: &otg.PatternFlowIpv4Version{
						Choice: &ipVersionValues,
					},
				},
			}},
		},
		wantErr: true,
	}, {
		desc: "ipv4 in MPLS - invalid specific version",
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
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Uint32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Uint32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Uint32(1),
					},
				},
			}, {
				Choice: &v4Choice,
				Ipv4: &otg.FlowIpv4{
					Src: &otg.PatternFlowIpv4Src{
						Choice: &srcIPValue,
						Value:  proto.String("1.1.1.1"),
					},
					Dst: &otg.PatternFlowIpv4Dst{
						Choice: &dstIPValue,
						Value:  proto.String("2.2.2.2"),
					},
					Version: &otg.PatternFlowIpv4Version{
						Choice: &ipVersionValue,
						Value:  proto.Uint32(42),
					},
				},
			}},
		},
		wantErr: true,
	}}

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
			if diff := cmp.Diff(got[0:len(got)-1], tt.wantLayers, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("did not get expected layers, diff(-got,+want):\n%s", diff)
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
