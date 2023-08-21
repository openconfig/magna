package lwotg

import (
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog"
)

// TXRXFn is a function that handles the send and receive of packets for a particular flow.
// When called it should begin tranmitting packets using the tx FlowController channels, and
// receiving them using the rx FlowController. Tx and Rx should be spawned into new goroutines
// and the function should return. Telemetry that is published by the flow should be written
// to the corresponding FlowController GNMI channel. Encountered errors should be written to
// the error channel.
type TXRXFn func(tx, rx *FlowController)

// FlowController acts as the control mechanism for a specific direction of a specific flow.
type FlowController struct {
	// Stop is a channel used to indicate that the function that has been called should
	// cease to send or receive packets.
	Stop chan struct{}
}

// NewFlowController returns an initialised FlowController.
func NewFlowController() *FlowController {
	return &FlowController{
		Stop: make(chan struct{}),
	}
}

// FlowGeneratorFn is a function that takes an input OTG Flow and, if it is able to, returns
// a TXRXFn that controls that flow. If the function is not able to handle the flow (e.g., it
// is an IP flow and the function can handle only MPLS) it returns no TXRXFn, and sets the
// bool return argument to false. If the function can handle the flow, it returns a TXRXFn that
// can be used to start the flow, with the bool return argument set to true. Errors encountered
// whilst generating a TXRXFn for a flow that the function can return should be returned and
// are treated as errors that should be returned to the caller.
//
// The arguments to a FlowGeneratorFn are as follows:
//   - otg.Flow - the flow that is to be generated as described by the OTG schema.
//   - []*OTGIntf - information as to the set of interfaces that are currently within the OTG
//     configuration. This information can be used to map the flow creation functionality to
//     the underlying interface.
type FlowGeneratorFn func(*otg.Flow, []*OTGIntf) (TXRXFn, bool, error)

// AddFlowHandlers adds the set of flow generator functions specified to the flow handlers that
// are considered as candidates by the server.
func (s *Server) AddFlowHandlers(fns ...FlowGeneratorFn) {
	s.fhMu.Lock()
	defer s.fhMu.Unlock()
	s.flowHandlers = append(s.flowHandlers, fns...)
}

// handleFlows takes the set of flows provided and returns the TXRX functions that control them.
// It returns an error if a flow cannot be handled by the registered set of flow handlers.
func (s *Server) handleFlows(flows []*otg.Flow) ([]TXRXFn, error) {
	s.fhMu.Lock()
	defer s.fhMu.Unlock()

	seenNames := map[string]struct{}{}

	flowMethods := []TXRXFn{}
	intfs := s.interfaces()
	for _, flow := range flows {
		var handled bool
		if _, ok := seenNames[flow.GetName()]; ok {
			return nil, status.Errorf(codes.InvalidArgument, "duplicate flow name: %s", flow.GetName())
		}

		for _, fn := range s.flowHandlers {
			txrx, ok, err := fn(flow, intfs)
			switch {
			case err != nil:
				// The flow could be handled, but an error occurred.
				return nil, status.Errorf(codes.Internal, "error generating flows, %v", err)
			case !ok:
				continue
			default:
				klog.Infof("flow %s was handled", flow.GetName())
				flowMethods = append(flowMethods, txrx)
				handled = true
			}
			if handled {
				break
			}
		}
		if !handled {
			return nil, status.Errorf(codes.Unimplemented, "no handler for flow %s", flow.GetName())
		}
		seenNames[flow.GetName()] = struct{}{}
	}
	return flowMethods, nil
}

// startTraffic triggers traffic generation for the defined sets of flows.
func (s *Server) startTraffic() {
	s.tgMu.Lock()
	defer s.tgMu.Unlock()

	s.generatorChs = []*FlowController{}
	klog.Infof("starting traffic...")
	for _, fn := range s.trafficGenerators {
		tx, rx := NewFlowController(), NewFlowController()
		go fn(tx, rx)
		s.generatorChs = append(s.generatorChs, []*FlowController{tx, rx}...)
		klog.Infof("started listener number %d", len(s.generatorChs))
	}
}

// stopTraffic stops the running generator functions.
func (s *Server) stopTraffic() {
	s.tgMu.Lock()
	defer s.tgMu.Unlock()

	for _, c := range s.generatorChs {
		c.Stop <- struct{}{}
	}
}
