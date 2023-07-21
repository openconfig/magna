//go:build !race

package lwotg

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestSetControlState(t *testing.T) {

	okResponse := &otg.SetControlStateResponse{}
	state := "UNKNOWN"
	trafficStart := otg.StateTrafficFlowTransmit_State_start
	trafficStop := otg.StateTrafficFlowTransmit_State_stop
	trafficPause := otg.StateTrafficFlowTransmit_State_pause
	trafficResume := otg.StateTrafficFlowTransmit_State_resume

	tests := []struct {
		desc              string
		inProtocolHandler func(*otg.Config, otg.StateProtocolAll_State_Enum) error
		inTrafficFunc     []TXRXFn
		inRequest         *otg.SetControlStateRequest
		wantResponse      *otg.SetControlStateResponse
		wantErrCode       codes.Code
		wantFn            func(t *testing.T)
	}{{
		desc: "port state - unimplemented",
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_port,
			},
		},
		wantErrCode: codes.Unimplemented,
	}, {
		desc: "protocol state for individual protocol",
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_protocol,
				Protocol: &otg.StateProtocol{
					Choice: otg.StateProtocol_Choice_route,
				},
			},
		},
		wantErrCode: codes.Unimplemented,
	}, {
		desc: "protocol state for all - with nil protocol handler",
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_protocol,
				Protocol: &otg.StateProtocol{
					Choice: otg.StateProtocol_Choice_all,
					All: &otg.StateProtocolAll{
						State: otg.StateProtocolAll_State_start,
					},
				},
			},
		},
		wantResponse: okResponse,
	}, {
		desc: "protocol state for all - with specified protocol handler",
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_protocol,
				Protocol: &otg.StateProtocol{
					Choice: otg.StateProtocol_Choice_all,
					All: &otg.StateProtocolAll{
						State: otg.StateProtocolAll_State_start,
					},
				},
			},
		},
		inProtocolHandler: func(_ *otg.Config, r otg.StateProtocolAll_State_Enum) error {
			switch r {
			case otg.StateProtocolAll_State_start:
				state = "START"
			case otg.StateProtocolAll_State_stop:
				state = "STOP"
			}
			return nil
		},
		wantResponse: okResponse,
		wantFn: func(t *testing.T) {
			t.Helper()
			if state != "START" {
				t.Fatalf("did not get expected state, got: %s, want: START", state)
			}
		},
	}, {
		desc: "traffic state with handler",
		inTrafficFunc: []TXRXFn{
			func(_, _ *FlowController) {
				state = "TRAFFIC_CALLED"
			},
		},
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_traffic,
				Traffic: &otg.StateTraffic{
					Choice: otg.StateTraffic_Choice_flow_transmit, // unspecified is alt operation
					FlowTransmit: &otg.StateTrafficFlowTransmit{
						State: &trafficStart,
					},
				},
			},
		},
		wantResponse: okResponse,
		wantFn: func(t *testing.T) {
			t.Helper()
			time.Sleep(200 * time.Millisecond)
			if state != "TRAFFIC_CALLED" {
				t.Fatalf("did not get expected state, got: %s, want: TRAFFIC_CALLED", state)
			}
		},
	}, {
		desc: "traffic state with unspecified operation",
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_traffic,
				Traffic: &otg.StateTraffic{
					Choice: otg.StateTraffic_Choice_unspecified,
				},
			},
		},
		wantErrCode: codes.Unimplemented,
	}, {
		desc: "traffic state with stop operation",
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_traffic,
				Traffic: &otg.StateTraffic{
					Choice: otg.StateTraffic_Choice_flow_transmit, // unspecified is alt operation
					FlowTransmit: &otg.StateTrafficFlowTransmit{
						State: &trafficStop,
					},
				},
			},
		},
		wantResponse: okResponse,
	}, {
		desc: "traffic state with pause operation",
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_traffic,
				Traffic: &otg.StateTraffic{
					Choice: otg.StateTraffic_Choice_flow_transmit, // unspecified is alt operation
					FlowTransmit: &otg.StateTrafficFlowTransmit{
						State: &trafficPause,
					},
				},
			},
		},
		wantErrCode: codes.Unimplemented,
	}, {
		desc: "traffic state with resume operation",
		inRequest: &otg.SetControlStateRequest{
			ControlState: &otg.ControlState{
				Choice: otg.ControlState_Choice_traffic,
				Traffic: &otg.StateTraffic{
					Choice: otg.StateTraffic_Choice_flow_transmit, // unspecified is alt operation
					FlowTransmit: &otg.StateTrafficFlowTransmit{
						State: &trafficResume,
					},
				},
			},
		},
		wantErrCode: codes.Unimplemented,
	}}

	for _, tt := range tests {
		state = "UNKNOWN"
		t.Run(tt.desc, func(t *testing.T) {
			lw := New()
			lw.SetProtocolHandler(tt.inProtocolHandler)
			lw.setTrafficGenFns(tt.inTrafficFunc)

			l, err := net.Listen("tcp", "localhost:0")
			if err != nil {
				t.Fatalf("cannot listen, %v", err)
			}
			t.Cleanup(func() { l.Close() })

			s := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
			otg.RegisterOpenapiServer(s, lw)
			go s.Serve(l)
			t.Cleanup(s.Stop)

			conn, err := grpc.Dial(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("cannot dial server %s, err: %v", l.Addr().String(), err)
			}
			c := otg.NewOpenapiClient(conn)

			got, err := c.SetControlState(context.Background(), tt.inRequest)
			if err != nil {
				if gotErr := status.Code(err); gotErr != tt.wantErrCode {
					t.Fatalf("did not get expected error, got code: %s (%v), want: %s", gotErr, err, tt.wantErrCode)
				}
			}

			if diff := cmp.Diff(got, tt.wantResponse, protocmp.Transform()); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}

			if tt.wantFn != nil {
				tt.wantFn(t)
			}
		})
	}
}

func TestSetConfig(t *testing.T) {
	okResponse := &otg.SetConfigResponse{}
	tests := []struct {
		desc             string
		inConfigHandlers []func(*otg.Config) error
		inFlowHandlers   []FlowGeneratorFn
		inRequest        *otg.SetConfigRequest
		wantResponse     *otg.SetConfigResponse
		wantErr          bool
		wantFn           func(t *testing.T)
	}{{
		desc:      "no config",
		inRequest: &otg.SetConfigRequest{},
		wantErr:   true,
	}, {
		desc: "error from config handler",
		inConfigHandlers: []func(*otg.Config) error{
			func(_ *otg.Config) error {
				return fmt.Errorf("got error")
			},
		},
		inRequest: &otg.SetConfigRequest{
			Config: &otg.Config{},
		},
		wantErr: true,
	}, {
		desc: "successfully run config handler",
		inConfigHandlers: []func(*otg.Config) error{
			func(_ *otg.Config) error {
				return nil
			},
		},
		inRequest: &otg.SetConfigRequest{
			Config: &otg.Config{},
		},
		wantResponse: okResponse,
	}, {
		desc: "error in flow handler",
		inFlowHandlers: []FlowGeneratorFn{
			func(*otg.Flow, []*OTGIntf) (TXRXFn, bool, error) {
				return nil, false, fmt.Errorf("cannot parse")
			},
		},
		inRequest: &otg.SetConfigRequest{
			Config: &otg.Config{
				Flows: []*otg.Flow{{
					Name: "flow1",
				}},
			},
		},
		wantErr: true,
	}, {
		desc: "generated flow",
		inFlowHandlers: []FlowGeneratorFn{
			func(*otg.Flow, []*OTGIntf) (TXRXFn, bool, error) {
				return func(_, _ *FlowController) {}, true, nil
			},
		},
		inRequest: &otg.SetConfigRequest{
			Config: &otg.Config{
				Flows: []*otg.Flow{{
					Name: "flow1",
				}},
			},
		},
		wantResponse: okResponse,
	}}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			lw := New()

			lw.configHandlers = tt.inConfigHandlers
			lw.flowHandlers = tt.inFlowHandlers

			l, err := net.Listen("tcp", "localhost:0")
			if err != nil {
				t.Fatalf("cannot listen, %v", err)
			}
			t.Cleanup(func() { l.Close() })

			s := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
			otg.RegisterOpenapiServer(s, lw)
			go s.Serve(l)
			t.Cleanup(s.Stop)

			conn, err := grpc.Dial(l.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("cannot dial server %s, err: %v", l.Addr().String(), err)
			}
			c := otg.NewOpenapiClient(conn)

			got, err := c.SetConfig(context.Background(), tt.inRequest)
			if (err != nil) != tt.wantErr {
				t.Fatalf("got unexpected error sending request (%s), err: %v", tt.inRequest, err)
			}

			if diff := cmp.Diff(got, tt.wantResponse, protocmp.Transform()); diff != "" {
				t.Fatalf("did not get expected result, diff(-got,+want):\n%s", diff)
			}

			if tt.wantFn != nil {
				tt.wantFn(t)
			}
		})
	}
}
