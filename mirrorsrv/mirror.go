package mirrorsrv

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	mpb "github.com/openconfig/magna/proto/mirror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog"
)

type Server struct {
	*mpb.UnimplementedMirrorServer

	stopMu  sync.Mutex
	stopChs map[string]chan struct{}
}

func New() *Server {
	return &Server{
		stopChs: map[string]chan struct{}{},
	}
}

var (
	// copyFunc can be overloaded during unit testing to avoid the need to have
	// physical interfaces available to test again.
	copyFunc = copyPackets
	// filterFunc can be overloaded during unit testing to avoid the need to
	// fake packets.
	filterFunc = mplsFilter
)

var (
	// pcapTimeout specifies the timeout for packet captures to be established.
	pcapTimeout = 30 * time.Second
)

const (
	// packetSize specifies the number of bytes that are to be read from the wire.
	packetSize = 9000
)

// mplsFilter returns true if a packet is an MPLS unicast packet.
func mplsFilter(p gopacket.Packet) bool {
	e, ok := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if !ok {
		return false
	}
	if e.EthernetType != layers.EthernetTypeMPLSUnicast {
		return false
	}
	klog.Infof("copying packet, %v", p)
	return true
}

// copyPackets returns a function that copies packets that are received on the 'from' interface
// to the 'to' interface. The packets match the specified filter function.
func copyPackets(from, to string, filter func(p gopacket.Packet) bool) func(chan struct{}) {
	return func(stop chan struct{}) {
		klog.Infof("launching goroutine to copy from %s->%s", from, to)
		ih, err := pcap.NewInactiveHandle(from)
		if err != nil {
			klog.Errorf("cannot open interface %s for reading, %v", from, err)
			return
		}
		if err := ih.SetImmediateMode(true); err != nil {
			klog.Errorf("cannot set immediate mode for interface %s, %v", from, err)
			return
		}
		if err := ih.SetPromisc(true); err != nil {
			klog.Errorf("cannot set promiscuous mode for interface %s, %v", from, err)
			return
		}
		if err := ih.SetSnapLen(packetSize); err != nil {
			klog.Errorf("cannot set capture length to %d for interface %s, %v", packetSize, from, err)
			return
		}
		rx, err := ih.Activate()
		if err != nil {
			klog.Errorf("cannot open rx interface %s, %v", from, err)
			return
		}
		defer rx.Close()

		tx, err := pcap.OpenLive(to, packetSize, true, pcapTimeout)
		if err != nil {
			klog.Errorf("cannot open tx interface %s, %v", to, err)
			return
		}
		defer tx.Close()

		ps := gopacket.NewPacketSource(rx, rx.LinkType())
		for {
			select {
			case <-stop:
				klog.Infof("stopping goroutine that copies from %s->%s", from, to)
				return
			case p := <-ps.Packets():
				if !filter(p) {
					klog.Infof("ignoring packet %v", p)
					continue
				}

				if err := tx.WritePacketData(p.Data()); err != nil {
					klog.Errorf("cannot write packet to tx interface %s, err: %v", to, err)
					return
				}
			}
		}
	}
}

func key(from, to string) string {
	return fmt.Sprintf("%s:%s", from, to)
}

func (s *Server) sessionExists(from, to string) bool {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	if _, ok := s.stopChs[key(from, to)]; ok {
		return true
	}
	return false
}

func (s *Server) addSession(from, to string, c chan struct{}) {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	s.stopChs[key(from, to)] = c
}

func (s *Server) stopSession(from, to string) {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	s.stopChs[key(from, to)] <- struct{}{}
	delete(s.stopChs, key(from, to))
}

func (s *Server) Start(ctx context.Context, req *mpb.StartRequest) (*mpb.StartResponse, error) {
	if req.From == "" || req.To == "" {
		return nil, status.Errorf(codes.InvalidArgument, "unspecified from or to in request, got: %s", req)
	}
	if s.sessionExists(req.From, req.To) {
		return nil, status.Errorf(codes.AlreadyExists, "session between %s and %s already exists", req.From, req.To)
	}

	fn := copyFunc(req.From, req.To, filterFunc)
	stop := make(chan struct{})
	s.addSession(req.From, req.To, stop)
	go fn(stop)
	return &mpb.StartResponse{}, nil
}

func (s *Server) Stop(ctx context.Context, req *mpb.StopRequest) (*mpb.StopResponse, error) {
	if req.From == "" || req.To == "" {
		return nil, status.Errorf(codes.InvalidArgument, "unspecified from or to in request, got: %s", req)
	}
	if !s.sessionExists(req.From, req.To) {
		return nil, status.Errorf(codes.NotFound, "cannot find session between %s and %s", req.From, req.To)
	}
	s.stopSession(req.From, req.To)
	return &mpb.StopResponse{}, nil
}
