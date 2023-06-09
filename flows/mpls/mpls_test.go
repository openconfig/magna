package mpls

import (
	"net"
	"testing"
	"time"

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

func TestFlowUpdateTX(t *testing.T) {
	tests := []struct {
		desc       string
		inCounters *flowCounters
		inPPS      int64
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
				Octets: &val{ts: 42, i: 1000},
				Pkts:   &val{ts: 42, i: 10},
			},
			Rx: &stats{},
		},
	}, {
		desc: "tx: append to existing packet count",
		inCounters: &flowCounters{
			Tx: &stats{
				Rate:   &val{ts: 1, f: 100},
				Octets: &val{ts: 1, i: 200},
				Pkts:   &val{ts: 1, i: 300},
			},
		},
		inPPS:  100,
		inSize: 20,
		want: &flowCounters{
			Tx: &stats{
				Rate:   &val{ts: 42, f: 100},
				Octets: &val{ts: 42, i: 2200},
				Pkts:   &val{ts: 42, i: 400},
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
				Octets: &val{ts: 1e9, i: 10},
				Pkts:   &val{ts: 1e9, i: 1},
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
				Octets: &val{ts: 1e9, i: 30},
				Pkts:   &val{ts: 1e9, i: 2},
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
				Octets: &val{ts: 2e9 + 1, i: 40},
				Pkts:   &val{ts: 2e9 + 1, i: 3},
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
				Octets: &val{ts: 1e9, i: 4000},
				Pkts:   &val{ts: 1e9, i: 200},
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
				Octets: &val{ts: 2e9 + 1, i: 4030},
				Pkts:   &val{ts: 2e9 + 1, i: 202},
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
