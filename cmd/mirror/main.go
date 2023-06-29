// Binary mirror implements a simple mechansim
package main

import (
	"flag"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"k8s.io/klog/v2"
)

var (
	from = flag.String("from", "eth1", "interface to copy packets from")
	to   = flag.String("to", "eth2", "interface to copy packets to")
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	var wg sync.WaitGroup
	wg.Add(1)
	go copyPackets(*from, *to, mplsFilter)()
	wg.Wait()
	// Time to flush logs.
	time.Sleep(2 * time.Second)
}

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
func copyPackets(from, to string, filter func(p gopacket.Packet) bool) func() {
	return func() {
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
			klog.Errorf("cannot set capture length to %d for interace %s, %v", packetSize, from, err)
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
		for p := range ps.Packets() {

			if !filter(p) {
				continue
			}

			if err := tx.WritePacketData(p.Data()); err != nil {
				klog.Errorf("cannot write packet to tx interface %s, err: %v", to, err)
				return
			}
		}
	}
}
