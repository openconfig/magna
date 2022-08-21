// Package lwotg implements a lightweight, extensible OTG implementation.
package lwotg

import (
	"context"

	"github.com/open-traffic-generator/snappi/gosnappi/otg"
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

	// TODO(robjs): Add support for:
	//   - functions that handle interface configuration.
	//   - functions that handle protocol configuration.
	//   - functions that handle flow configuration.
	//   - functions that handle traffic generation.

	// cfg is a cache of the current OTG configuration.
	cfg *otg.Config
}

// New returns a new lightweight OTG (LWOTG) server.
func New() *Server {
	return &Server{}
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
