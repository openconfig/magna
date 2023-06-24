package mpls

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmi/value"
	"github.com/openconfig/ygot/testutil"
	"github.com/openconfig/ygot/ygot"
	"google.golang.org/protobuf/proto"
)

func TestHeaders(t *testing.T) {
	v4Choice := otg.FlowHeader_Choice_ipv4
	v6Choice := otg.FlowHeader_Choice_ipv6
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

	dstIPValue := otg.PatternFlowIpv4Dst_Choice_value
	dstIPValues := otg.PatternFlowIpv4Dst_Choice_values
	srcIPValue := otg.PatternFlowIpv4Src_Choice_value
	srcIPValues := otg.PatternFlowIpv4Src_Choice_values
	ipVersionValue := otg.PatternFlowIpv4Version_Choice_value
	ipVersionValues := otg.PatternFlowIpv4Version_Choice_values

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
						Value:  proto.Int32(4),
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
						Value:  proto.Int32(4),
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
						Value:  proto.Int32(4),
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
						Value:  proto.Int32(42),
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

func TestFlowUpdateTX(t *testing.T) {
	tests := []struct {
		desc       string
		inCounters *flowCounters
		inPPS      int
		inSize     int
		want       *flowCounters
	}{{
		desc:       "tx: packet counters initialised",
		inCounters: newFlowCounters(),
		inPPS:      10,
		inSize:     100,
		want: &flowCounters{
			Tx: &stats{
				Rate:   &val{ts: 42, f: 10},
				Octets: &val{ts: 42, u: 1000},
				Pkts:   &val{ts: 42, u: 10},
			},
			Rx: &stats{},
		},
	}, {
		desc: "tx: append to existing packet count",
		inCounters: &flowCounters{
			Tx: &stats{
				Rate:   &val{ts: 1, f: 100},
				Octets: &val{ts: 1, u: 200},
				Pkts:   &val{ts: 1, u: 300},
			},
		},
		inPPS:  100,
		inSize: 20,
		want: &flowCounters{
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

			got := newFlowCounters()
			if tt.inCounters != nil {
				got = tt.inCounters
			}

			got.updateTx(tt.inPPS, tt.inSize)

			if diff := cmp.Diff(got, tt.want, cmpopts.IgnoreUnexported(stats{}), cmpopts.IgnoreUnexported(flowCounters{}), cmp.AllowUnexported(val{})); diff != "" {
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
		inCounters *flowCounters
		inPackets  []pktArrival
		want       *flowCounters
	}{{
		desc: "single packet arriving",
		inPackets: []pktArrival{{
			t: time.Unix(1, 0),
			s: 10,
		}},
		want: &flowCounters{
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
		want: &flowCounters{
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
		want: &flowCounters{
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
		inCounters: &flowCounters{
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
		want: &flowCounters{
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
			got := newFlowCounters()
			if tt.inCounters != nil {
				got = tt.inCounters
			}

			for _, p := range tt.inPackets {
				got.updateRx(p.t, p.s)
			}

			if diff := cmp.Diff(got, tt.want, cmpopts.IgnoreUnexported(stats{}), cmpopts.IgnoreUnexported(flowCounters{}), cmp.AllowUnexported(val{})); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

func TestLossPct(t *testing.T) {
	tests := []struct {
		desc string
		in   *flowCounters
		want float32
	}{{
		desc: "no loss",
		in: &flowCounters{
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
		in: &flowCounters{
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
		in: &flowCounters{
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
		in: &flowCounters{
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
		in   *flowCounters
		want float32
	}{{
		desc: "full sliding window",
		in: &flowCounters{
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
		in: &flowCounters{
			Timeseries: map[int64]int{
				1: 10,
			},
		},
		want: 0,
	}, {
		desc: "no entries",
		in:   &flowCounters{},
		want: 0,
	}, {
		desc: "fewer than sliding window entries",
		in: &flowCounters{
			Timeseries: map[int64]int{
				1: 10,
				2: 10,
				3: 10,
			},
		},
		want: 80.0,
	}, {
		desc: "average required",
		in: &flowCounters{
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

func mustNoti(t *testing.T, ts int64, upd ...updSpec) *gpb.Notification {
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
		Timestamp: ts,
		Update:    updates,
	}
}

func TestTelemetry(t *testing.T) {
	tests := []struct {
		desc string
		in   *flowCounters
		want []*gpb.Notification
	}{{
		desc: "empty input",
		in:   newFlowCounters(),
	}, {
		desc: "tx statistics",
		in: &flowCounters{
			Name: &val{ts: 1, s: "flow_one"},
			Tx: &stats{
				Pkts:   &val{ts: 100, u: 100},
				Octets: &val{ts: 100, u: 800},
				Rate:   &val{ts: 100, f: 8000},
			},
			Transmit: &val{ts: 120, b: true},
		},
		want: []*gpb.Notification{
			mustNoti(t, 1,
				updSpec{path: "/flows/flow[name=flow_one]/name", val: "flow_one"},
				updSpec{path: "/flows/flow[name=flow_one]/state/name", val: "flow_one"}),
			mustNoti(t, 120, updSpec{path: "/flows/flow[name=flow_one]/state/transmit", val: true}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/out-pkts", val: uint64(100)}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/out-octets", val: uint64(800)}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/out-rate", val: []byte{0, 0, 250, 69}}),
		},
	}, {
		desc: "rx statistics",
		in: &flowCounters{
			Name: &val{ts: 1, s: "flow_one"},
			Rx: &stats{
				Pkts:   &val{ts: 100, u: 100},
				Octets: &val{ts: 100, u: 800},
			},
			Transmit: &val{ts: 120, b: true},
		},
		want: []*gpb.Notification{
			mustNoti(t, 1,
				updSpec{path: "/flows/flow[name=flow_one]/name", val: "flow_one"},
				updSpec{path: "/flows/flow[name=flow_one]/state/name", val: "flow_one"}),
			mustNoti(t, 120, updSpec{path: "/flows/flow[name=flow_one]/state/transmit", val: true}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/in-pkts", val: uint64(100)}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/in-octets", val: uint64(800)}),
			mustNoti(t, 42, updSpec{path: "/flows/flow[name=flow_one]/state/in-rate", val: []byte{0, 0, 0, 0}}),
		},
	}, {
		desc: "tx and rx",
		in: &flowCounters{
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
		want: []*gpb.Notification{
			mustNoti(t, 1,
				updSpec{path: "/flows/flow[name=flow_one]/name", val: "flow_one"},
				updSpec{path: "/flows/flow[name=flow_one]/state/name", val: "flow_one"}),
			mustNoti(t, 120, updSpec{path: "/flows/flow[name=flow_one]/state/transmit", val: true}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/out-pkts", val: uint64(100)}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/out-octets", val: uint64(800)}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/out-rate", val: []byte{0, 0, 250, 69}}),
			mustNoti(t, 120, updSpec{path: "/flows/flow[name=flow_one]/state/transmit", val: true}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/in-pkts", val: uint64(0)}),
			mustNoti(t, 100, updSpec{path: "/flows/flow[name=flow_one]/state/counters/in-octets", val: uint64(800)}),
			mustNoti(t, 42, updSpec{path: "/flows/flow[name=flow_one]/state/in-rate", val: []byte{0, 0, 128, 65}}),
			mustNoti(t, 42, updSpec{path: "/flows/flow[name=flow_one]/state/loss-pct", val: []byte{0, 0, 200, 66}}),
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

				s += fmt.Sprintf("%d: %s: %v\n", n.Timestamp, p, v)
			}
		}
		return s
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if got := tt.in.telemetry(); !testutil.NotificationSetEqual(got, tt.want) {

				t.Fatalf("did not get expected set of notifications, got: \n%s\nwant:\n%s", shortNoti(got), shortNoti(tt.want))
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

func TestRxPacket(t *testing.T) {
	simplePacket := []gopacket.SerializableLayer{
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
			DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
			EthernetType: layers.EthernetTypeMPLSUnicast,
		},
		&layers.MPLS{
			Label:       42,
			TTL:         100,
			StackBottom: true,
		},
		&layers.IPv4{
			Version: 4,
			SrcIP:   net.ParseIP("1.2.3.4"),
			DstIP:   net.ParseIP("2.3.4.5"),
		},
		gopacket.Payload([]byte{1, 2, 3, 4}),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, simplePacket...)
	simplePkt := buf.Bytes()
	inSimple := gopacket.NewPacket(simplePkt, layers.LinkTypeEthernet, gopacket.Default)

	fixedTimeFn := func() time.Time { return time.Date(2023, 06, 12, 10, 00, 00, 00, time.UTC) }

	type packetWithTime struct {
		timeFn func() time.Time
		packet gopacket.Packet
	}

	tests := []struct {
		desc         string
		inCounters   *flowCounters
		inHeaders    []gopacket.SerializableLayer
		inPackets    []packetWithTime
		wantCounters *flowCounters
	}{{
		desc:       "matched increments empty counters",
		inCounters: newFlowCounters(),
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{},
			&layers.MPLS{},
			&layers.IPv4{
				Version: 4,
				SrcIP:   net.ParseIP("1.2.3.4"),
				DstIP:   net.ParseIP("2.3.4.5"),
			},
			gopacket.Payload([]byte{2, 3, 4, 5}),
		},
		inPackets: []packetWithTime{{
			timeFn: fixedTimeFn,
			packet: inSimple,
		}},
		wantCounters: &flowCounters{
			Tx: &stats{},
			Rx: &stats{
				Octets: &val{ts: 1686564000000000000, u: 60},
				Pkts:   &val{ts: 1686564000000000000, u: 1},
			},
			Timeseries: map[int64]int{1686564000: 60},
		},
	}, {
		desc:       "matched - two packets",
		inCounters: newFlowCounters(),
		inHeaders: []gopacket.SerializableLayer{
			&layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, 0},
				DstMAC:       net.HardwareAddr{1, 2, 3, 4, 5, 6},
				EthernetType: layers.EthernetTypeMPLSUnicast,
			},
			&layers.IPv4{
				Version: 4,
				SrcIP:   net.ParseIP("1.2.3.4"),
				DstIP:   net.ParseIP("2.3.4.5"),
			},
			gopacket.Payload([]byte{4, 5, 6, 7}),
		},
		inPackets: []packetWithTime{{
			timeFn: fixedTimeFn,
			packet: inSimple,
		}, {
			timeFn: func() time.Time { return time.Date(2023, 06, 12, 10, 00, 01, 00, time.UTC) },
			packet: inSimple,
		}},
		wantCounters: &flowCounters{
			Tx: &stats{},
			Rx: &stats{
				Octets: &val{ts: 1686564001000000000, u: 120},
				Pkts:   &val{ts: 1686564001000000000, u: 2},
			},
			Timeseries: map[int64]int{
				1686564000: 60,
				1686564001: 60,
			},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			for _, p := range tt.inPackets {
				timeFn = p.timeFn
				rxPacket(tt.inCounters, tt.inHeaders, p.packet)
			}
			if diff := cmp.Diff(tt.inCounters, tt.wantCounters, cmpopts.IgnoreUnexported(stats{}), cmp.AllowUnexported(val{}), cmpopts.IgnoreUnexported(flowCounters{})); diff != "" {
				t.Fatalf("did not get expected counters, diff(-got,+want):\n%s", diff)
			}
		})
	}
	timeFn = time.Now
}

func TestDecode(t *testing.T) {
	mac := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	ip := net.IP{0, 1, 2, 3}
	p := make([]byte, 64, 64)
	pkt := []gopacket.SerializableLayer{
		&layers.Ethernet{
			SrcMAC:       mac,
			DstMAC:       mac,
			EthernetType: layers.EthernetTypeMPLSUnicast,
		},
		&layers.MPLS{
			Label:       uint32(42),
			TTL:         42,
			StackBottom: true,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    ip,
			DstIP:    ip,
			Protocol: layers.IPProtocolTCP,
		},
		gopacket.Payload(p),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, pkt...)
	simplePkt := buf.Bytes()
	fmt.Printf("%v\n", simplePkt)
	inSimple := gopacket.NewPacket(simplePkt, layers.LinkTypeEthernet, gopacket.Lazy)
	ip4 := inSimple.Layer(layers.LayerTypeIPv4)
	fmt.Printf("%#v\n", ip4)
	fmt.Printf("%v\n", inSimple.ErrorLayer())

	v := packetInFlow(pkt, inSimple)
	fmt.Printf("in flow? %v\n", v)
}
