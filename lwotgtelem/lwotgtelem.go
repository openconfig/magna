// Package lwotgtelem implements a gNMI server that serves OTG telemetry.
package lwotgtelem

import (
	"context"
	"fmt"
	"sync"

	"github.com/openconfig/magna/lwotg"
	"github.com/openconfig/magna/lwotgtelem/gnmit"
	"k8s.io/klog/v2"
)

// HintMap is a structured set of hints that are supplied by the server, it
// consists of a map keyed by the name of a hints group, that contains a map
// of hint key to hint value.
type HintMap map[string]map[string]string

// Server contains the implementation of the gNMI server.
type Server struct {
	// c is the base gnmit Collector implementation that is used to store updates.
	c *gnmit.Collector
	// GNMIServer is the gNMI gRPC server instance that can be exposed externally.
	GNMIServer *gnmit.GNMIServer

	// hintCh is a channel that is used to write hints into the telemetry server
	// Hints are used to allow data to be mapped to the OTG schema -- and may
	// consist of elements of the OTG configuration, or mappings between underlying
	// resources (e.g., physical interfaces) and the names they are referred to in
	// OTG.
	//
	// Hints are defined in the lwotg package, and are <group, key, value>
	// tuples.
	hintCh chan lwotg.Hint

	// hintsMu protects the hints map.
	hintsMu sync.RWMutex
	// hints is the set of Hints that have been received by the Server via the
	// hint channel.
	hints HintMap
}

// New returns a new LWOTG gNMI server. The hostname is used to specify the hostname of the OTG server
// that the server is acting for.
func New(ctx context.Context, hostname string) (*Server, error) {
	// defaultTasks is the set of tasks that should be run by default to populate telemetry values.
	defaultTasks := []gnmit.Task{}

	c, g, err := gnmit.NewServer(ctx, hostname, true, defaultTasks)
	if err != nil {
		return nil, fmt.Errorf("cannot create gnmit server, %v", err)
	}

	return &Server{
		c:          c,
		GNMIServer: g,
		hints:      HintMap{},
	}, nil
}

// SetHintChannel sets the channel that hints will be received by the telemetry server on.
func (s *Server) SetHintChannel(ctx context.Context, ch chan lwotg.Hint) {
	s.hintCh = ch
	go func() {
		for {
			select {
			case h := <-s.hintCh:
				s.SetHint(h.Group, h.Key, h.Value)
			case <-ctx.Done():
				return
			}
		}
	}()
}

// SetHint stores the value of the hint specified in the server cache.
func (s *Server) SetHint(group, key, val string) {
	s.hintsMu.Lock()
	defer s.hintsMu.Unlock()

	klog.Infof("Setting hint %s:%s = %s", group, key, val)
	if _, ok := s.hints[group]; !ok {
		s.hints[group] = map[string]string{}
	}
	s.hints[group][key] = val
}

// GetHints returns all the hints that the lwotg implementation currently knows
// about.
func (s *Server) GetHints() HintMap {
	s.hintsMu.RLock()
	defer s.hintsMu.RUnlock()

	// We want to return a copy so that the user can't modify it, so
	// walk the map to copy it.
	m := HintMap{}
	for gk, gv := range s.hints {
		m[gk] = map[string]string{}
		for k, v := range gv {
			m[gk][k] = v
		}
	}
	return m
}

// GetHint returns the value of the specified hint, it returns 'ok' as false if it is
// not found.
func (s *Server) GetHint(group, key string) (value string, ok bool) {
	s.hintsMu.RLock()
	defer s.hintsMu.RUnlock()

	if _, gok := s.hints[group]; !gok {
		return "", false
	}

	value, ok = s.hints[group][key]
	return
}

// AddTask adds the task t to the current tasks run by the gNMI server. Tasks are
// functions that produce telemetry information that is to be published by gNMI.
func (s *Server) AddTask(t gnmit.Task) error {
	return s.GNMIServer.RegisterTask(t)
}
