package common

import (
	"testing"

	"github.com/google/gopacket"
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
