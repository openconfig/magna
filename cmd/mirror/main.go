// Binary mirror implements a simple mechanism to copy packets that match
// a filter between ports.
package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/openconfig/magna/mirrorsrv"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"

	mpb "github.com/openconfig/magna/proto/mirror"
)

var (
	port = flag.Uint("port", 60051, "port for mirror service to listen on")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	srv := grpc.NewServer()
	ms := mirrorsrv.New()
	mpb.RegisterMirrorServer(srv, ms)

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		klog.Exitf("cannot start listening, got err: %v", err)
	}

	defer srv.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go srv.Serve(lis)
	wg.Wait()
	// Time to flush logs.
	time.Sleep(2 * time.Second)
}
