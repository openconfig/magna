package lwotg

import (
	"fmt"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestStartStopTraffic(t *testing.T) {
	var (
		dataMu sync.Mutex
		wg     sync.WaitGroup
	)
	data := []string{}
	addData := func(s string) {
		dataMu.Lock()
		defer dataMu.Unlock()
		data = append(data, s)
	}
	tests := []struct {
		desc                string
		inTrafficGenerators []TXRXFn
		wantData            []string
	}{{
		desc: "single traffic generator function",
		inTrafficGenerators: []TXRXFn{
			func(tx, rx *FlowController) {
				go func() {
					addData("tx")
					<-tx.Stop
				}()
				go func() {
					addData("rx")
					<-rx.Stop
				}()
			},
		},
		wantData: []string{"tx", "rx"},
	}, {
		desc: "two traffic generator functions",
		inTrafficGenerators: []TXRXFn{
			func(tx, rx *FlowController) {
				wg.Add(2)
				go func() {
					addData("tx0")
					<-tx.Stop
					addData("exit-tx0")
					wg.Done()
				}()
				go func() {
					addData("rx0")
					<-rx.Stop
					addData("exit-rx0")
					wg.Done()
				}()
				wg.Wait()
			},
			func(tx, rx *FlowController) {
				wg.Add(2)
				go func() {
					addData("tx1")
					<-tx.Stop
					addData("exit-tx1")
					wg.Done()
				}()
				go func() {
					addData("rx1")
					<-rx.Stop
					addData("exit-rx1")
					wg.Done()
				}()
				wg.Wait()
			},
		},
		wantData: []string{
			"tx0", "rx0", "tx1", "rx1",
			"exit-rx0", "exit-tx0", "exit-rx1", "exit-tx1", // check that the goroutines got stop signals.
		},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			defer func() { data = []string{} }()
			s := &Server{}
			s.trafficGenerators = tt.inTrafficGenerators
			s.startTraffic()
			s.stopTraffic()
			// wait for the goroutines to exit such that we can be sure that we got
			// all the append operations.
			wg.Wait()

			if diff := cmp.Diff(data, tt.wantData, cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}), cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("did not get expected data, diff(-got,+want):\n%s", diff)
			}
		})
	}

}
