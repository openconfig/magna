package lwotg

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestSetProtocols(t *testing.T) {

	okResponse := &otg.SetProtocolStateResponse{
		StatusCode_200: &otg.ResponseWarning{},
	}

	state := "UNKNOWN"

	tests := []struct {
		desc              string
		inProtocolHandler func(*otg.Config, otg.ProtocolState_State_Enum) error
		inRequest         *otg.SetProtocolStateRequest
		wantResponse      *otg.SetProtocolStateResponse
		wantFn            func(t *testing.T)
	}{{
		desc: "start with nil protocol handler",
		inRequest: &otg.SetProtocolStateRequest{
			ProtocolState: &otg.ProtocolState{
				State: otg.ProtocolState_State_start,
			},
		},
		wantResponse: okResponse,
	}, {
		desc: "protocol handler called",
		inProtocolHandler: func(_ *otg.Config, r otg.ProtocolState_State_Enum) error {
			switch r {
			case otg.ProtocolState_State_start:
				state = "START"
			case otg.ProtocolState_State_stop:
				state = "STOP"
			}
			return nil
		},
		inRequest: &otg.SetProtocolStateRequest{
			ProtocolState: &otg.ProtocolState{
				State: otg.ProtocolState_State_start,
			},
		},
		wantResponse: okResponse,
		wantFn: func(t *testing.T) {
			t.Helper()
			if state != "START" {
				t.Fatalf("did not get expected state, got: %s, want: START", state)
			}
		},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			lw := New()
			lw.SetProtocolHandler(tt.inProtocolHandler)

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

			got, err := c.SetProtocolState(context.Background(), tt.inRequest)
			if err != nil {
				t.Fatalf("got error sending request (%s), err: %v", tt.inRequest, err)
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
	okResponse := &otg.SetConfigResponse{
		StatusCode_200: &otg.ResponseWarning{},
	}
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
			func(*otg.Flow, []*otgIntf) (TXRXFn, bool, error) {
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
			func(*otg.Flow, []*otgIntf) (TXRXFn, bool, error) {
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
