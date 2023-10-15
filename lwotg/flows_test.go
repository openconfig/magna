package lwotg

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

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
			func(_ *otg.Flow, _ []*OTGIntf) (TXRXFn, bool, error) {
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
			func(_ *otg.Flow, _ []*OTGIntf) (TXRXFn, bool, error) {
				return func(tx, rx *FlowController) {}, true, nil
			},
		},
		wantMethods: []TXRXFn{dummyFn, dummyFn},
	}, {
		desc: "duplicate flow names",
		inFlows: []*otg.Flow{{
			Name: "flow0",
		}, {
			Name: "flow0",
		}},
		inFns: []FlowGeneratorFn{
			func(_ *otg.Flow, _ []*OTGIntf) (TXRXFn, bool, error) {
				return func(tx, rx *FlowController) {}, true, nil
			},
		},
		wantErrCode: codes.InvalidArgument,
	}, {
		desc: "flow handler that returns an error",
		inFlows: []*otg.Flow{{
			Name: "error",
		}},
		inFns: []FlowGeneratorFn{
			func(_ *otg.Flow, _ []*OTGIntf) (TXRXFn, bool, error) {
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
		inTrafficGenerators []*TXRXWrapper
		wantData            []string
		after               func(*testing.T, *Server, chan struct{})
	}{{
		desc: "single traffic generator function",
		inTrafficGenerators: []*TXRXWrapper{{
			Name: "flow",
			Fn: func(tx, rx *FlowController) {
				go func() {
					addData("tx")
					<-tx.Stop
				}()
				go func() {
					addData("rx")
					<-rx.Stop
				}()
			},
		}},
		wantData: []string{"tx", "rx"},
	}, {
		desc: "two traffic generator functions",
		inTrafficGenerators: []*TXRXWrapper{{
			Name: "FN1",
			Fn: func(tx, rx *FlowController) {
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
			},
		}, {
			Name: "FN2",
			Fn: func(tx, rx *FlowController) {
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
			},
		}},
		wantData: []string{
			"tx0", "rx0", "tx1", "rx1",
			"exit-rx0", "exit-tx0", "exit-rx1", "exit-tx1", // check that the goroutines got stop signals.
		},
	}, {
		desc: "many traffic generator functions",
		inTrafficGenerators: func() []*TXRXWrapper {
			f := []*TXRXWrapper{}
			for i := 0; i < 254; i++ {
				ns := fmt.Sprintf("%d", i)
				f = append(f, &TXRXWrapper{
					Name: fmt.Sprintf("f%d", i),
					Fn: func(tx, rx *FlowController) {
						wg.Add(2)
						go func() {
							addData("tx" + ns)
							<-tx.Stop
							addData("exit-tx" + ns)
							wg.Done()
						}()
						go func() {
							addData("rx" + ns)
							<-rx.Stop
							addData("exit-rx" + ns)
							wg.Done()
						}()
					},
				})
			}
			return f
		}(),
		wantData: func() []string {
			s := []string{}
			for i := 0; i < 254; i++ {
				s = append(s, []string{
					fmt.Sprintf("tx%d", i),
					fmt.Sprintf("rx%d", i),
					fmt.Sprintf("exit-tx%d", i),
					fmt.Sprintf("exit-rx%d", i),
				}...)
			}
			return s
		}(),
	}, {
		desc: "badly behaved traffic generator function",
		inTrafficGenerators: []*TXRXWrapper{{
			Name: "bad",
			Fn: func(tx, rx *FlowController) {
				wg.Add(2)
				go func() {
					addData("start-tx")
					time.Sleep(10 * time.Second)
					// We don't ever read from the stop channel - which is not correct.
					wg.Done()
				}()
				go func() {
					addData("start-rx")
					<-rx.Stop
					addData("exit-rx")
					wg.Done()
				}()
			},
		}},
		wantData: []string{
			"start-tx", "start-rx", "exit-rx",
		},
		// Check that after we have a stale traffic generator routine, we can still send a config
		// request. This ensures that there are no stale locks held.
		after: func(t *testing.T, s *Server, waitCh chan struct{}) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			exited := make(chan struct{}, 1)
			go func(ctx context.Context, exited, waitCh chan struct{}) {
				select {
				case <-exited:
				case <-ctx.Done():
					t.Errorf("context completed, configuration set hung, %v", ctx.Err())
				}
				waitCh <- struct{}{}
			}(ctx, exited, waitCh)
			_, _ = s.SetConfig(ctx, &otg.SetConfigRequest{
				Config: &otg.Config{},
			})
			exited <- struct{}{}
		},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			defer func() { data = []string{} }()
			s := &Server{}
			s.trafficGenerators = tt.inTrafficGenerators
			s.startTraffic()
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			defer cancel()
			s.stopTraffic(ctx)
			// wait for the goroutines to exit such that we can be sure that we got
			// all the append operations.
			wg.Wait()

			if diff := cmp.Diff(data, tt.wantData, cmpopts.SortSlices(func(a, b string) bool {
				return a < b
			}), cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("did not get expected data, diff(-got,+want):\n%s", diff)
			}

			if tt.after != nil {
				waitCh := make(chan struct{})
				tt.after(t, s, waitCh)
				<-waitCh
			}
		})
	}

}
