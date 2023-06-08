package lwotgtelem

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/openconfig/lemming/gnmi/gnmit"
	"github.com/openconfig/magna/lwotg"
	"github.com/openconfig/ygot/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	certFile = "testdata/cert.pem"
	keyFile  = "testdata/key.pem"
)

func TestNew(t *testing.T) {
	tests := []struct {
		desc        string
		inHostname  string
		inPaths     []*gpb.Path
		inTask      []gnmit.Task
		wantResults []*gpb.Notification
		wantErr     bool
	}{{
		desc:       "successful subscription",
		inHostname: "ate",
	}, {
		desc:       "task that writes /hello",
		inHostname: "ate",
		inPaths:    []*gpb.Path{{Elem: []*gpb.PathElem{{Name: "hello"}}}},
		inTask: []gnmit.Task{
			{
				Run: func(_ gnmit.Queue, updateFn gnmit.UpdateFn, target string, _ func()) error {
					if err := updateFn(&gpb.Notification{
						Timestamp: 42,
						Prefix: &gpb.Path{
							Origin: "openconfig",
							Target: target,
						},
						Update: []*gpb.Update{{
							Path: &gpb.Path{
								Elem: []*gpb.PathElem{
									{Name: "hello"},
								},
							},
							Val: &gpb.TypedValue{
								Value: &gpb.TypedValue_StringVal{
									StringVal: "world",
								},
							},
						}},
					}); err != nil {
						return err
					}
					return nil
				},
			},
		},
		wantResults: []*gpb.Notification{{
			Timestamp: 42,
			Prefix: &gpb.Path{
				Origin: "openconfig",
				Target: "ate",
			},
			Update: []*gpb.Update{{
				Path: &gpb.Path{Elem: []*gpb.PathElem{{Name: "hello"}}},
				Val: &gpb.TypedValue{
					Value: &gpb.TypedValue_StringVal{
						StringVal: "world",
					},
				},
			}},
		}},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			srv, err := New(context.Background(), tt.inHostname)
			if (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error, got: %v, wantErr? %v", err, tt.wantErr)
			}

			for _, r := range tt.inTask {
				if err := srv.AddTask(r); err != nil {
					t.Fatalf("cannot register task, err: %v", err)
				}
			}

			l, err := net.Listen("tcp", "localhost:0")
			if err != nil {
				t.Fatalf("cannot listen, got err: %v", err)
			}
			t.Cleanup(func() { l.Close() })

			creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
			if err != nil {
				t.Fatalf("cannot create TLS credentials, got err: %v", err)
			}

			s := grpc.NewServer(grpc.Creds(creds))
			gpb.RegisterGNMIServer(s, srv.GNMIServer)

			go s.Serve(l)
			t.Cleanup(s.Stop)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			conn, err := grpc.DialContext(ctx, l.Addr().String(),
				grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
					InsecureSkipVerify: true,
				})))
			if err != nil {
				t.Fatalf("cannot gRPC dial, err: %v", err)
			}
			c := gpb.NewGNMIClient(conn)

			stream, err := c.Subscribe(ctx)
			if err != nil {
				t.Fatalf("cannot subscribe, err: %v", err)
			}

			subs := []*gpb.Subscription{}
			for _, p := range tt.inPaths {
				subs = append(subs, &gpb.Subscription{Path: p})
			}

			if err := stream.Send(&gpb.SubscribeRequest{
				Request: &gpb.SubscribeRequest_Subscribe{
					Subscribe: &gpb.SubscriptionList{
						Prefix: &gpb.Path{
							Target: tt.inHostname,
							Origin: "openconfig",
						},
						Subscription: subs,
						Mode:         gpb.SubscriptionList_ONCE,
					},
				},
			}); err != nil {
				t.Fatalf("cannot subscribe to lwotgtelem server, err: %v", err)
			}

			got := []*gpb.Notification{}
			for {
				msg, err := stream.Recv()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("got error receiving from lwotgtelem server, err: %v", err)
				}

				// only record cases where we receive Notifications.
				if u := msg.GetUpdate(); u != nil {
					got = append(got, u)
				}
			}

			t.Logf("got results, %v", got)
			if !testutil.NotificationSetEqual(got, tt.wantResults) {
				t.Fatalf("did not get expected notification set, got: %v, want: %v", got, tt.wantResults)
			}
		})
	}
}

func TestHint(t *testing.T) {
	tests := []struct {
		desc         string
		inHints      []lwotg.Hint
		wantHints    []lwotg.Hint
		wantNotFound bool
	}{{
		desc: "single hint",
		inHints: []lwotg.Hint{{
			Group: "interfaces",
			Key:   "eth0",
			Value: "port-42",
		}},
		wantHints: []lwotg.Hint{{
			Group: "interfaces",
			Key:   "eth0",
			Value: "port-42",
		}},
	}, {
		desc: "multiple hints",
		inHints: []lwotg.Hint{{
			Group: "interfaces",
			Key:   "eth0",
			Value: "port-1",
		}, {
			Group: "interfaces",
			Key:   "eth1",
			Value: "port-2",
		}},
		wantHints: []lwotg.Hint{{
			Group: "interfaces",
			Key:   "eth0",
			Value: "port-1",
		}, {
			Group: "interfaces",
			Key:   "eth1",
			Value: "port-2",
		}},
	}, {
		desc: "no such hint",
		wantHints: []lwotg.Hint{{
			Group: "can't",
			Key:   "find",
			Value: "hint",
		}},
		wantNotFound: true,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ch := make(chan lwotg.Hint, 10)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := New(ctx, "ate")
			if err != nil {
				t.Fatalf("cannot create server, err: %v", err)
			}

			s.SetHintChannel(ctx, ch)
			for _, h := range tt.inHints {
				ch <- h
			}

			// deflake otherwise our test has timing issues.
			time.Sleep(100 * time.Millisecond)

			for _, want := range tt.wantHints {
				got, ok := s.GetHint(want.Group, want.Key)
				switch {
				case !ok && !tt.wantNotFound:
					t.Fatalf("did not find expected hint %v", want)
				case !ok && tt.wantNotFound:
				case got != want.Value:
					t.Fatalf("did not get expected hint value, got: %v, want: %v", got, want.Value)
				}
			}
		})
	}
}

func TestGetHints(t *testing.T) {
	tests := []struct {
		desc      string
		inHints   HintMap
		wantHints HintMap
	}{{
		desc: "no hints found",
	}, {
		desc: "one group",
		inHints: HintMap{
			"group": map[string]string{"key": "value"},
		},
		wantHints: HintMap{
			"group": map[string]string{"key": "value"},
		},
  }, {
    desc: "multiple groups",
    inHints: HintMap{
      "group1": map[string]string{"key1": "val1"},
      "group2": map[string]string{"key2": "val2"},
    },
    wantHints: HintMap{
      "group1": map[string]string{"key1": "val1"},
      "group2": map[string]string{"key2": "val2"},
    },
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			s := &Server{hints: tt.inHints}
			got := s.GetHints()
			if diff := cmp.Diff(got, tt.wantHints, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("s.GetHints(): did not get expected hints, diff(-got,+want):\n%s", diff)
			}
		})
	}
}
