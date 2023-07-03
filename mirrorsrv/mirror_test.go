package mirrorsrv

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/google/gopacket"
	mpb "github.com/openconfig/magna/proto/mirror"
)

func startServer(t *testing.T) (*Server, string) {
	t.Helper()
	srv := grpc.NewServer()
	ms := New()
	mpb.RegisterMirrorServer(srv, ms)

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("cannot start server, %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return ms, lis.Addr().String()
}

func TestStart(t *testing.T) {

	var called []string
	tests := []struct {
		desc       string
		inReq      *mpb.StartRequest
		inSessions map[string]chan struct{}
		inFunc     func(string, string, func(p gopacket.Packet) bool) func(chan struct{})
		wantCode   codes.Code
		wantCalled []string
	}{{
		desc:     "empty input",
		inReq:    &mpb.StartRequest{},
		wantCode: codes.InvalidArgument,
	}, {
		desc:     "no from",
		inReq:    &mpb.StartRequest{To: "eth2"},
		wantCode: codes.InvalidArgument,
	}, {
		desc:     "no to",
		inReq:    &mpb.StartRequest{From: "eth3"},
		wantCode: codes.InvalidArgument,
	}, {
		desc:       "existing session",
		inReq:      &mpb.StartRequest{From: "eth1", To: "eth2"},
		inSessions: map[string]chan struct{}{"eth1:eth2": make(chan struct{})},
		wantCode:   codes.AlreadyExists,
	}, {
		desc:  "create new session",
		inReq: &mpb.StartRequest{From: "eth1", To: "eth2"},
		inFunc: func(from, to string, _ func(p gopacket.Packet) bool) func(chan struct{}) {
			called = append(called, fmt.Sprintf("%s:%s", from, to))
			return func(_ chan struct{}) {}
		},
		wantCalled: []string{"eth1:eth2"},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {

			if tt.inFunc != nil {
				copyFunc = tt.inFunc
				t.Cleanup(func() { copyFunc = copyPackets })
			}

			ms, addr := startServer(t)
			conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("got error in grpc.Dial(%v), got err: %v", addr, err)
			}

			if tt.inSessions != nil {
				ms.stopChs = tt.inSessions
			}

			client := mpb.NewMirrorClient(conn)
			got, err := client.Start(context.Background(), tt.inReq)
			t.Logf("got: %s %v", got, err)
			if err != nil {
				s, ok := status.FromError(err)
				if !ok {
					t.Fatalf("did not get correct return type, %v", err)
				}
				if s.Code() != tt.wantCode {
					t.Fatalf("did not get expected error code, got: %v, want: %v", s.Code(), tt.wantCode)
				}
			}

			if tt.inFunc != nil {
				t.Logf("got called value: %v", called)
				if !reflect.DeepEqual(tt.wantCalled, called) {
					t.Fatalf("did not get expected called, got: %v, want: %v", called, tt.wantCalled)
				}
			}
			called = []string{}
		})
	}
}

func TestStop(t *testing.T) {
	called := false
	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	tests := []struct {
		desc         string
		inReq        *mpb.StopRequest
		inSessions   map[string]chan struct{}
		inListenFunc func()
		wantCode     codes.Code
	}{{
		desc:     "empty input",
		inReq:    &mpb.StopRequest{},
		wantCode: codes.InvalidArgument,
	}, {
		desc:     "no from",
		inReq:    &mpb.StopRequest{To: "eth2"},
		wantCode: codes.InvalidArgument,
	}, {
		desc:     "no to",
		inReq:    &mpb.StopRequest{From: "eth3"},
		wantCode: codes.InvalidArgument,
	}, {
		desc:       "session does not exist",
		inReq:      &mpb.StopRequest{From: "eth42", To: "eth2"},
		inSessions: map[string]chan struct{}{"eth1:eth2": make(chan struct{})},
		wantCode:   codes.NotFound,
	}, {
		desc:       "create new session",
		inReq:      &mpb.StopRequest{From: "eth1", To: "eth2"},
		inSessions: map[string]chan struct{}{"eth1:eth2": stopCh},
		inListenFunc: func() {
			<-stopCh
			called = true
			wg.Done()
		},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {

			if tt.inListenFunc != nil {
				wg.Add(1)
				go tt.inListenFunc()
			}

			ms, addr := startServer(t)
			conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("got error in grpc.Dial(%v), got err: %v", addr, err)
			}

			if tt.inSessions != nil {
				ms.stopChs = tt.inSessions
			}

			client := mpb.NewMirrorClient(conn)
			got, err := client.Stop(context.Background(), tt.inReq)
			t.Logf("got: %s %v", got, err)
			if err != nil {
				s, ok := status.FromError(err)
				if !ok {
					t.Fatalf("did not get correct return type, %v", err)
				}
				if s.Code() != tt.wantCode {
					t.Fatalf("did not get expected error code, got: %v, want: %v", s.Code(), tt.wantCode)
				}
			}

			wg.Wait()
			if tt.inListenFunc != nil {
				t.Logf("checking for value of called, got: %v", called)
				if called != true {
					t.Fatalf("did not get expected called value, got: %v, want: true", called)
				}
			}

			called = false
		})
	}
}
