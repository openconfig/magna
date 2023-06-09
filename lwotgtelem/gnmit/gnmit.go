// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gnmit is a single-target gNMI collector implementation that can be
// used as an on-device/fake device implementation. It supports the Subscribe RPC
// using the libraries from openconfig/gnmi.
package gnmit

import (
	"context"
	"fmt"
	"net"
	"time"

	log "github.com/golang/glog"
	"github.com/openconfig/gnmi/cache"
	"github.com/openconfig/magna/lwotgtelem/gnmit/subscribe"
	"github.com/openconfig/ygot/ygot"
	"google.golang.org/grpc"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

var (
	// metadataUpdatePeriod is the period of time after which the metadata for the collector
	// is updated to the client.
	metadataUpdatePeriod = 30 * time.Second
	// sizeUpdatePeriod is the period of time after which the storage size information for
	// the collector is updated to the client.
	sizeUpdatePeriod = 30 * time.Second
)

// periodic runs the function fn every period.
func periodic(period time.Duration, fn func()) {
	if period == 0 {
		return
	}
	t := time.NewTicker(period)
	defer t.Stop()
	for range t.C {
		fn()
	}
}

// Queue is an interface that represents a possibly coalescing queue of updates.
type Queue interface {
	Next(ctx context.Context) (interface{}, uint32, error)
	Len() int
	Close()
}

// UpdateFn is a function that takes in a gNMI Notification object and updates
// a gNMI datastore with it.
type UpdateFn func(*gpb.Notification) error

// TaskRoutine is a reactor function that listens for updates from a queue,
// emits updates via an update function. It does this on a target (string
// parameter), and also has a final clean-up function to call when it finishes
// processing.
type TaskRoutine func(Queue, UpdateFn, string, func()) error

// Task defines a particular task that runs on the gNMI datastore.
type Task struct {
	Run    TaskRoutine
	Paths  []ygot.PathStruct
	Prefix *gpb.Path
}

// GNMIServer implements the gNMI server interface.
type GNMIServer struct {
	// The subscribe Server implements only Subscribe for gNMI.
	*subscribe.Server
	c *Collector
}

// RegisterTask starts up a task on the gNMI datastore.
func (s *GNMIServer) RegisterTask(task Task) error {
	var paths []*gpb.Path
	for _, p := range task.Paths {
		path, _, err := ygot.ResolvePath(p)
		if err != nil {
			return fmt.Errorf("gnmit: cannot register task: %v", err)
		}
		paths = append(paths, path)
	}
	queue, remove, err := s.Server.SubscribeLocal(s.c.name, paths, task.Prefix)
	if err != nil {
		return err
	}
	return task.Run(queue, s.c.cache.GnmiUpdate, s.c.name, remove)
}

// New returns a new collector server implementation that can be registered on
// an existing gRPC server. It takes a string indicating the hostname of the
// target, a boolean indicating whether metadata should be sent, and a slice of
// tasks that are to be launched to run on the server.
func NewServer(ctx context.Context, hostname string, sendMeta bool, tasks []Task) (*Collector, *GNMIServer, error) {
	c := &Collector{
		inCh: make(chan *gpb.SubscribeResponse),
		name: hostname,
	}

	c.cache = cache.New([]string{hostname})
	t := c.cache.GetTarget(hostname)

	if sendMeta {
		go periodic(metadataUpdatePeriod, c.cache.UpdateMetadata)
		go periodic(sizeUpdatePeriod, c.cache.UpdateSize)
	}
	t.Connect()

	// start our single collector from the input channel.
	go func() {
		for {
			select {
			case msg := <-c.inCh:
				if err := c.handleUpdate(msg); err != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	subscribeSrv, err := subscribe.NewServer(c.cache)
	if err != nil {
		return nil, nil, fmt.Errorf("could not instantiate gNMI server: %v", err)
	}

	gnmiserver := &GNMIServer{
		Server: subscribeSrv, // use the 'subscribe' implementation.
		c:      c,
	}

	for _, t := range tasks {
		if err := gnmiserver.RegisterTask(t); err != nil {
			return nil, nil, err
		}
	}
	c.cache.SetClient(subscribeSrv.Update)

	return c, gnmiserver, nil
}

// New returns a new collector that listens on the specified addr (in the form host:port),
// supporting a single downstream target named hostname. sendMeta controls whether the
// metadata *other* than meta/sync and meta/connected is sent by the collector.
//
// New returns the new collector, the address it is listening on in the form hostname:port
// or any errors encounted whilst setting it up.
func New(ctx context.Context, addr, hostname string, sendMeta bool, tasks []Task, opts ...grpc.ServerOption) (*Collector, string, error) {
	c, gnmiserver, err := NewServer(ctx, hostname, sendMeta, tasks)
	if err != nil {
		return nil, "", err
	}
	srv := grpc.NewServer(opts...)
	gpb.RegisterGNMIServer(srv, gnmiserver)
	// Forward streaming updates to clients.
	// Register listening port and start serving.
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, "", fmt.Errorf("failed to listen: %v", err)
	}

	go func() {
		if err := srv.Serve(lis); err != nil {
			log.Errorf("Error while serving gnmi target: %v", err)
		}
	}()
	c.stopFn = srv.GracefulStop
	return c, lis.Addr().String(), nil
}

// Stop halts the running collector.
func (c *Collector) Stop() {
	c.stopFn()
}

// handleUpdate handles an input gNMI SubscribeResponse that is received by
// the target.
func (c *Collector) handleUpdate(resp *gpb.SubscribeResponse) error {
	t := c.cache.GetTarget(c.name)
	switch v := resp.Response.(type) {
	case *gpb.SubscribeResponse_Update:
		return t.GnmiUpdate(v.Update)
	case *gpb.SubscribeResponse_SyncResponse:
		t.Sync()
	case *gpb.SubscribeResponse_Error:
		return fmt.Errorf("error in response: %s", v)
	default:
		return fmt.Errorf("unknown response %T: %s", v, v)
	}
	return nil
}

// Collector is a basic gNMI target that supports only the Subscribe
// RPC, and acts as a cache for exactly one target.
type Collector struct {
	cache *cache.Cache

	// name is the hostname of the client.
	name string
	// inCh is a channel use to write new SubscribeResponses to the client.
	inCh chan *gpb.SubscribeResponse
	// stopFn is the function used to stop the server.
	stopFn func()
}

// TargetUpdate provides an input gNMI SubscribeResponse to update the
// cache and clients with.
func (c *Collector) TargetUpdate(m *gpb.SubscribeResponse) {
	c.inCh <- m
}
