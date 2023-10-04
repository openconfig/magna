package common

import (
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"github.com/openconfig/magna/lwotg"
	"google.golang.org/protobuf/proto"
)

func TestPorts(t *testing.T) {
	devValue := otg.FlowTxRx_Choice_device
	portValue := otg.FlowTxRx_Choice_port

	tests := []struct {
		desc           string
		inFlow         *otg.Flow
		inIntfs        []*lwotg.OTGIntf
		wantTx, wantRx string
		wantErr        bool
	}{{
		desc: "invalid flow type",
		inFlow: &otg.Flow{
			TxRx: &otg.FlowTxRx{
				Choice: &devValue,
			},
		},
		wantErr: true,
	}, {
		desc: "missing interfaces",
		inFlow: &otg.Flow{
			TxRx: &otg.FlowTxRx{
				Choice: &portValue,
				Port: &otg.FlowPort{
					TxName:  "port1",
					RxNames: []string{"port2"},
				},
			},
		},
		wantErr: true,
	}, {
		desc: "valid specification",
		inFlow: &otg.Flow{
			TxRx: &otg.FlowTxRx{
				Choice: &portValue,
				Port: &otg.FlowPort{
					TxName:  "port1",
					RxNames: []string{"port2"},
				},
			},
		},
		inIntfs: []*lwotg.OTGIntf{{
			OTGPortName: "port1",
			SystemName:  "eth0",
		}, {
			OTGPortName: "port2",
			SystemName:  "eth1",
		}},
		wantTx: "eth0",
		wantRx: "eth1",
	}, {
		desc: "valid legacy specification",
		inFlow: &otg.Flow{
			TxRx: &otg.FlowTxRx{
				Choice: &portValue,
				Port: &otg.FlowPort{
					TxName: "port1",
					RxName: proto.String("port2"), // Note, this field is to be deprecated.
				},
			},
		},
		inIntfs: []*lwotg.OTGIntf{{
			OTGPortName: "port1",
			SystemName:  "eth0",
		}, {
			OTGPortName: "port2",
			SystemName:  "eth1",
		}},
		wantTx: "eth0",
		wantRx: "eth1",
	}, {
		desc: "multiple rx ports",
		inFlow: &otg.Flow{
			TxRx: &otg.FlowTxRx{
				Choice: &portValue,
				Port: &otg.FlowPort{
					TxName:  "port1",
					RxNames: []string{"port1", "port2"},
				},
			},
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			gotTx, gotRx, err := Ports(tt.inFlow, tt.inIntfs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error, got: %v, wantErr? %v", err, tt.wantErr)
			}
			if got, want := gotTx, tt.wantTx; got != want {
				t.Errorf("did not get expected Tx port, got: %s, want: %s", got, want)
			}
			if got, want := gotRx, tt.wantRx; got != want {
				t.Errorf("did not get expected Rx port, got: %s, want: %s", got, want)
			}
		})
	}
}

func TestRate(t *testing.T) {
	rateBPS := otg.FlowRate_Choice_bps
	ratePPS := otg.FlowRate_Choice_pps

	tests := []struct {
		desc      string
		inFlow    *otg.Flow
		inHeaders []gopacket.SerializableLayer
		wantPPS   uint64
		wantErr   bool
	}{{
		desc: "invalid specification",
		inFlow: &otg.Flow{
			Rate: &otg.FlowRate{
				Choice: &rateBPS,
			},
		},
		wantErr: true,
	}, {
		desc:    "default value",
		inFlow:  &otg.Flow{},
		wantPPS: 1000,
	}, {
		desc: "explicit value",
		inFlow: &otg.Flow{
			Rate: &otg.FlowRate{
				Choice: &ratePPS,
				Pps:    proto.Uint64(1234),
			},
		},
		wantPPS: 1234,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := Rate(tt.inFlow, tt.inHeaders)
			if (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error, got: %v, wantErr? %v", err, tt.wantErr)
			}
			if want := tt.wantPPS; got != want {
				t.Fatalf("did not get expected PPS, got: %d, want: %d", got, want)
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
		inCounters   *counters
		inHeaders    []gopacket.SerializableLayer
		inPackets    []packetWithTime
		wantCounters *counters
	}{{
		desc:       "matched increments empty counters",
		inCounters: NewCounters(),
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
		wantCounters: &counters{
			Tx: &stats{},
			Rx: &stats{
				Octets: &val{ts: 1686564000000000000, u: 60},
				Pkts:   &val{ts: 1686564000000000000, u: 1},
			},
			Timeseries: map[int64]int{1686564000: 60},
		},
	}, {
		desc:       "matched - two packets",
		inCounters: NewCounters(),
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
		wantCounters: &counters{
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
				rxPacket(tt.inCounters, p.packet, true)
			}
			if diff := cmp.Diff(tt.inCounters, tt.wantCounters, cmpopts.IgnoreUnexported(stats{}), cmp.AllowUnexported(val{}), cmpopts.IgnoreUnexported(counters{})); diff != "" {
				t.Fatalf("did not get expected counters, diff(-got,+want):\n%s", diff)
			}
		})
	}
	timeFn = time.Now
}

