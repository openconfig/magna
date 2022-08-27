package lwotg

import (
	"fmt"
	"testing"

	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestHandleFlows(t *testing.T) {
	dummyFn := func(_, _ *FlowController) {}

	tests := []struct {
		desc        string
		inFlows     []*otg.Flow
		inFns       []FlowGeneratorFn
		wantMethods []TXRXFn
		wantErrCode codes.Code
	}{{
		desc: "unhandled flow",
		inFlows: []*otg.Flow{{
			Name: "unhandled",
		}},
		wantErrCode: codes.Unimplemented,
	}, {
		desc: "handled flow",
		inFlows: []*otg.Flow{{
			Name: "handled",
		}},
		inFns: []FlowGeneratorFn{
			func(_ *otg.Flow, _ []*otgIntf) (TXRXFn, bool, error) {
				return func(tx, rx *FlowController) {}, true, nil
			},
		},
		wantMethods: []TXRXFn{dummyFn},
	}, {
		desc: "two flows handled",
		inFlows: []*otg.Flow{{
			Name: "handled-1",
		}, {
			Name: "handled-2",
		}},
		inFns: []FlowGeneratorFn{
			func(_ *otg.Flow, _ []*otgIntf) (TXRXFn, bool, error) {
				return func(tx, rx *FlowController) {}, true, nil
			},
		},
		wantMethods: []TXRXFn{dummyFn, dummyFn},
	}, {
		desc: "flow handler that returns an error",
		inFlows: []*otg.Flow{{
			Name: "error",
		}},
		inFns: []FlowGeneratorFn{
			func(_ *otg.Flow, _ []*otgIntf) (TXRXFn, bool, error) {
				return nil, true, fmt.Errorf("unhandled")
			},
		},
		wantErrCode: codes.Internal,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			s := &Server{}
			s.AddFlowHandlers(tt.inFns...)

			got, err := s.handleFlows(tt.inFlows)
			if err != nil {
				s, ok := status.FromError(err)
				if !ok {
					t.Fatalf("cannot parse error as a status.Status, for err: %v", err)
				}
				if gotErr := s.Code(); gotErr != tt.wantErrCode {
					t.Fatalf("did not get expected error code, got: %s, want: %s", gotErr, tt.wantErrCode)
				}
			}

			// Just compare length because we don't want to compare function pointer equality.
			if len(got) != len(tt.wantMethods) {
				t.Fatalf("did not get expected methods, got: %v, want: %v", got, tt.wantMethods)
			}
		})
	}

}
