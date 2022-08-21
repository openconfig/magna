// Package lwotg implements a lightweight, extensible OTG implementation.
package lwotg

import (
	"context"
	"net"
	"sync"

	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"github.com/openconfig/magna/intf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog"
)

// Hint is <group, key, value> tuple that can be handed to modules of the
// OTG implementation to perform their functions. For example, it may be
// used to communicate mappings between system interfaces and the names that
// are used in OTG for them.
type Hint struct {
	// Group is a string used to specify a name for a set of hints that
	// are associated one one another.
	Group string
	// Key is the name of the hint.
	Key string
	// Value is the value stored for the hint.
	Value string
}

const (
	// InterfaceHintGroupName is the name of the group that is used to
	// handle interface details.
	InterfaceHintGroupName string = "interface_map"
)

// Server implements the OTG ("Openapi") server.
type Server struct {
	*otg.UnimplementedOpenapiServer

	// hintCh is the a channel that is used to send hints about the configuration
	// to other elements of the OTG system. Particularly, it is used to send hints
	// to the telemetry mapping functions.
	hintCh chan Hint

	// protocolHandler is a function called when the OTG SetProtocolState RPC
	// is called. It is used to ensure that anything that needs to be done in
	// the underlying system is performed (e.g., ensuring ARP is populated, or
	// other daemons are started).
	protocolHandler func(*otg.Config, otg.ProtocolState_State_Enum) error

	// chMu protects the configHandlers slice.
	chMu sync.Mutex
	// configHandlers is a slice of functions that are called when the SetConfig
	// RPC is called. Each handles the configuration and returns an error if it
	// finds one. It is possible that multiple handlers read the same configuration
	// based on the registered handlers.
	configHandlers []func(*otg.Config) error

	// TODO(robjs): Add support for:
	//   - functions that handle protocol configuration.
	//   - functions that handle flow configuration.
	//   - functions that handle traffic generation.

	// cfg is a cache of the current OTG configuration.
	cfg *otg.Config
}

// New returns a new lightweight OTG (LWOTG) server.
func New() *Server {
	return &Server{
		configHandlers: []func(*otg.Config) error{
			s.baseInterfaceHandler,
		},
	}
}

// AddConfigHandler adds the specified fn to the set of config handlers.
func (s *Server) AddConfigHandler(fn func(*otg.Config) error) {
	s.chMu.Lock()
	defer s.chMu.Unlock()
	s.configHandlers = append(s.configHandlers, fn)
}

// SetHintChannel sets the hint channel to the specified channel.
func (s *Server) SetHintChannel(ch chan Hint) {
	s.hintCh = ch
}

// SetProtocolHandler sets the specified function as the function to be called when the
// SetPrrotocolState RPC is called.
func (s *Server) SetProtocolHandler(fn func(*otg.Config, otg.ProtocolState_State_Enum) error) {
	s.protocolHandler = fn
}

// SetProtocolState handles the SetProtocolState OTG call. In this implementation it calls the
// protocolHandler function that has been specified.
func (s *Server) SetProtocolState(ctx context.Context, req *otg.SetProtocolStateRequest) (*otg.SetProtocolStateResponse, error) {
	klog.Infof("Setting protocol state based on request, %s", req)
	if s.protocolHandler != nil {
		if err := s.protocolHandler(s.cfg, req.GetProtocolState().GetState()); err != nil {
			return nil, err
		}
	}
	return &otg.SetProtocolStateResponse{StatusCode_200: &otg.ResponseWarning{}}, nil
}

// SetConfig handles the SetConfig OTG RPC. In this implementation it calls the set
// of configHandlers that have been registered with the server.
func (s *Server) SetConfig(ctx context.Context, req *otg.SetConfigRequest) (*otg.SetConfigResponse, error) {
	if req.Config == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request configuration received, %v", req)
	}

	for _, fn := range s.configHandlers {
		if err := fn(req.Config); err != nil {
			return nil, err
		}
	}

	s.cfg = req.Config

	// TODO(robjs): remove this status 200 once OTG has been updated.
	return &otg.SetConfigResponse{StatusCode_200: &otg.ResponseWarning{}}, nil
}

// baseInterfaceHandler is a built-in handler for interface configuration which is used as a configHandler.
func (s *Server) baseInterfaceHandler(cfg *otg.Config) error {
	intfs, err := portsToSystem(cfg.Ports, cfg.Devices)
	if err != nil {
		return err
	}

	if s.hintCh != nil {
		for _, i := range intfs {
			h := Hint{
				Group: InterfaceHintGroupName,
				Key:   i.SystemName,
				Value: i.OTGEthernetName,
			}
			select {
			case s.hintCh <- h:
			default:
				// Non-blocking if the channel is full.
			}
		}
	}

	for _, i := range intfs {
		for _, a := range i.IPv4 {
			n := &net.IPNet{
				IP:   a.Address,
				Mask: net.CIDRMask(a.Mask, 32),
			}
			klog.Infof("Configuring interface %s with address %s", i.SystemName, n)
			if err := intf.AddIP(i.SystemName, a); err != nil {
				return status.Errorf(codes.Internal, "cannot configure address %s on interface %s, err: %v", n, i.SystemName, error)
			}
		}
	}
}
