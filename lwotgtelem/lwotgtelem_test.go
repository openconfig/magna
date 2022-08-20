package lwotgtelem

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/openconfig/lemming/gnmi/gnmit"
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
			gnmit.Task{
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
