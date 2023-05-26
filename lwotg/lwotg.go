// Package lwotg implements a lightweight, extensible OpenTrafficGenerator
// (github.com/open-traffic-generator) implementation. OpenTrafficGenerator is
// often abbreviated to OTG.
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
	// are associated with one another.
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

	// protocolHandler is a function called when the OTG SetControlState
	// with 'protocol' RPC is called. It is used to ensure that anything
	// that needs to be done in the underlying system is performed (e.g.,
	// ensuring ARP is populated, or other daemons are started).
	protocolHandler func(*otg.Config, otg.StateProtocolAll_State_Enum) error

	// chMu protects the configHandlers slice.
	chMu sync.Mutex
	// configHandlers is a slice of functions that are called when the SetConfig
	// RPC is called. Each handles the configuration and returns an error if it
	// finds one. It is possible that multiple handlers read the same configuration
	// based on the registered handlers.
	configHandlers []func(*otg.Config) error

	// fhMu protects the flowHandlers slice.
	fhMu sync.Mutex
	// flowHandlers is the a slice of functions that are called when the SetConfig
	// RPC is called which specifically handle flows. Each function is a FlowGeneratorFn
	// and is sequentially called to determine whether it can handle the flow.
	flowHandlers []FlowGeneratorFn

	// TODO(robjs): Add support for:
	//   - functions that handle protocol configuration.

	// cfg is a cache of the current OTG configuration.
	cfg *otg.Config

	// intMu protects the intfCache.
	intfMu sync.Mutex
	// intfCache is a cache of the current set of interfaces for the OTG configuration.
	intfCache []*OTGIntf

	// tgMu protects the trafficGenerators and generatorChs slices.
	tgMu sync.Mutex
	// trafficGenerators are the set of functions that will be called when the OTG server
	// is requested to start generating traffic.
	trafficGenerators []TXRXFn
	// generatorChs are the channels to communicate with the traffic generation functions.
	generatorChs []*FlowController
}

// New returns a new lightweight OTG (LWOTG) server.
func New() *Server {
	s := &Server{
		configHandlers: []func(*otg.Config) error{},
	}

	// Always run the baseInterfaceHandler built-in function.
	s.AddConfigHandler(s.baseInterfaceHandler)
	return s
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
// SetControlState RPC is called with protocol related options.
func (s *Server) SetProtocolHandler(fn func(*otg.Config, otg.StateProtocolAll_State_Enum) error) {
	s.protocolHandler = fn
}

// SetControlState handles the SetControlState OTG RPC. This implementation only supports:
//   - starting and stopping all protocols, by calling the protocolHandler function that has been specified.
//   - starting and stopping all traffic, by calling startTraffic and stopTraffic.
//
// It returns an error if an unsupported option is requested.
func (s *Server) SetControlState(ctx context.Context, req *otg.SetControlStateRequest) (*otg.SetControlStateResponse, error) {
	klog.Infof("Setting control state based on request, %s", req)

	switch st := req.GetControlState().GetChoice(); st {
	case otg.ControlState_Choice_protocol:
		if st := req.GetControlState().GetProtocol().GetChoice(); st != otg.StateProtocol_Choice_all {
			return nil, status.Errorf(codes.Unimplemented, "no support for enabling and disabling individual protocols, got: %s", st)
		}

		if s.protocolHandler != nil {
			if err := s.protocolHandler(s.cfg, req.GetControlState().GetProtocol().GetAll().GetState()); err != nil {
				return nil, err
			}
		}
	case otg.ControlState_Choice_traffic:
		switch a := req.GetControlState().GetTraffic().GetFlowTransmit().GetState(); a {
		case otg.StateTrafficFlowTransmit_State_start:
			s.startTraffic()
		case otg.StateTrafficFlowTransmit_State_stop:
			s.stopTraffic()
		default:
			return nil, status.Errorf(codes.Unimplemented, "traffic control modes other than start and stop are not implemented, got: %s", a)
		}
	default:
		return nil, status.Errorf(codes.Unimplemented, "got unimplemented control state request, %s", st)
	}
	return &otg.SetControlStateResponse{}, nil
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

	flowMethods, err := s.handleFlows(req.GetConfig().GetFlows())
	if err != nil {
		return nil, err
	}
	s.setTrafficGenFns(flowMethods)

	// Cache the configuration.
	s.cfg = req.Config

	return &otg.SetConfigResponse{}, nil
}

// setTrafficGenFns sets the functions that will be used to generate traffic
// for the flows within the configuration.
func (s *Server) setTrafficGenFns(fns []TXRXFn) {
	s.tgMu.Lock()
	defer s.tgMu.Unlock()
	s.trafficGenerators = fns
}

// interfaces returns a copy of the cached set of interfaces in the server.
func (s *Server) interfaces() []*OTGIntf {
	s.intfMu.Lock()
	defer s.intfMu.Unlock()

	return append([]*OTGIntf{}, s.intfCache...)
}

// baseInterfaceHandler is a built-in handler for interface configuration which is used as a configHandler.
func (s *Server) baseInterfaceHandler(cfg *otg.Config) error {
	intfs, err := portsToSystem(cfg.Ports, cfg.Devices)
	if err != nil {
		return err
	}

	// Stash the current set of interfaces as these are used by other callers.
	s.intfCache = intfs

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
			if err := intf.AddIP(i.SystemName, n); err != nil {
				return status.Errorf(codes.Internal, "cannot configure address %s on interface %s, err: %v", n, i.SystemName, err)
			}
		}
	}

	return nil
}
