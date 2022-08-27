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

func TestHeaders(t *testing.T) {
	v4Choice := otg.FlowHeader_Choice_ipv4
	mplsChoice := otg.FlowHeader_Choice_mpls
	ethernetChoice := otg.FlowHeader_Choice_ethernet

	dstMACValue := otg.PatternFlowEthernetDst_Choice_value
	dstMACValues := otg.PatternFlowEthernetDst_Choice_values

	srcMACValue := otg.PatternFlowEthernetSrc_Choice_value
	srcMACValues := otg.PatternFlowEthernetSrc_Choice_values

	mplsTTLValue := otg.PatternFlowMplsTimeToLive_Choice_value
	mplsTTLValues := otg.PatternFlowMplsTimeToLive_Choice_values
	mplsBOSValue := otg.PatternFlowMplsBottomOfStack_Choice_value
	mplsBOSValues := otg.PatternFlowMplsBottomOfStack_Choice_values
	mplsLabelValue := otg.PatternFlowMplsLabel_Choice_value
	mplsLabelValues := otg.PatternFlowMplsLabel_Choice_values

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
				Choice: &v4Choice,
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
						Value:  proto.Int32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Int32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Int32(1),
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
						Value:  proto.Int32(42),
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
						Value:  proto.Int32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Int32(2),
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
						Value:  proto.Int32(42),
					},
					TimeToLive: &otg.PatternFlowMplsTimeToLive{
						Choice: &mplsTTLValue,
						Value:  proto.Int32(2),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Int32(0),
					},
				},
			}, {
				Choice: &mplsChoice,
				Mpls: &otg.FlowMpls{
					Label: &otg.PatternFlowMplsLabel{
						Choice: &mplsLabelValue,
						Value:  proto.Int32(84),
					},
					BottomOfStack: &otg.PatternFlowMplsBottomOfStack{
						Choice: &mplsBOSValue,
						Value:  proto.Int32(1),
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
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := headers(tt.inFlow)
			if (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error, got: %v, wantErr? %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(got, tt.wantLayers, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("did not get expected layers, diff(-got,+want):\n%s", diff)
			}
		})
	}
}
