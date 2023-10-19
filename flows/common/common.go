// Package common providers common OTG flow helper functions.
package common

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"github.com/openconfig/magna/lwotg"
	"k8s.io/klog"
)

var (
	// packetBytes is the number of bytes to read from an input packet.
	packetBytes int = 100
)

// hdrsFunc is a function which specifies which packet headers to create. It is
// also used to determine the correctness of the headers received.
type hdrsFunc func(*otg.Flow) ([]gopacket.SerializableLayer, error)

// matchFunc is a function which determines if a packet p matchs the headers
// hdrs.
type matchFunc func(hdrs []gopacket.SerializableLayer, p gopacket.Packet) bool

// Handler creates a new flow generator function based on the header and match
// function provided.
func Handler(fn hdrsFunc, match matchFunc, reporter *Reporter) lwotg.FlowGeneratorFn {
	return func(flow *otg.Flow, intfs []*lwotg.OTGIntf) (lwotg.TXRXFn, bool, error) {
		hdrs, err := fn(flow)
		if err != nil {
			return nil, false, err
		}

		fc := NewCounters()
		fc.Headers = hdrs

		pps, err := Rate(flow, hdrs)
		if err != nil {
			return nil, false, fmt.Errorf("cannot calculate rate, %v", err)
		}

		packetsToSend, err := flowPackets(flow)
		if err != nil {
			return nil, false, fmt.Errorf("cannot extract number of flow packets, %v", err)
		}

		tx, rx, err := Ports(flow, intfs)
		if err != nil {
			return nil, false, fmt.Errorf("cannot determine ports, %v", err)
		}

		fc.Name = &val{s: flow.Name, ts: flowTimeFn()}
		klog.Infof("generating flow %s: tx: %s, rx: %s, rate: %d pps", flow.GetName(), tx, rx, pps)
		reporter.AddFlow(flow.Name, fc)

		// TODO(robjs): In the future we should wrap the PCAP handle in a library so that we can test our
		// logic by writing into a test. Today, we're relying on integration test coverage here.

		genFunc := func(controllerID string, stop, rxReady chan struct{}) {
			// Don't proceed to set up the transmit function until the listener has already been created
			// and is listening, this avoids us sending packets into the void when we know no-one is listening
			// for them to account the flow.
			<-rxReady

			f := reporter.Flow(flow.Name)
			klog.Infof("%s send function started.", flow.Name)
			f.clearStats(time.Now().UnixNano())

			buf := gopacket.NewSerializeBuffer()
			gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}, hdrs...)
			size := len(buf.Bytes())

			klog.Infof("%s Tx interface %s", flow.Name, tx)

			ih, err := pcap.NewInactiveHandle(tx)
			if err != nil {
				klog.Errorf("cannot create handle, err: %v", err)
				return
			}
			defer ih.CleanUp()
			if err := ih.SetImmediateMode(true); err != nil {
				klog.Errorf("cannot set immediate mode on handle, err: %v", err)
				return
			}

			if err := ih.SetPromisc(false); err != nil {
				klog.Errorf("cannot set promiscous mode, err: %v", err)
				return
			}

			if err := ih.SetSnapLen(packetBytes); err != nil {
				klog.Errorf("cannot set packet length, err: %v", err)
			}

			handle, err := ih.Activate()
			if err != nil {
				klog.Errorf("%s Tx error: %v", flow.Name, err)
				return
			}
			defer handle.Close()

			f.setTransmit(true)
			// runSentPackets is the total number of packets that we have sent this run - i.e., since we
			// were asked to start transmitting.
			runSentPackets := uint32(0)
			// stopFlow indicates whether we should stop sending packets on the flow, it is set
			// when the flow specification says that we should only send a limited number of
			// packets.
			var stopFlow bool
			for {
				select {
				case <-stop:
					klog.Infof("controller ID %s, flow %s, exiting on %s", controllerID, flow.Name, tx)
					f.setTransmit(false)
					return
				default:
					switch stopFlow {
					case true:
						// avoid busy looping.
						time.Sleep(100 * time.Millisecond)
					default:
						klog.Infof("%s sending %d packets", flow.Name, pps)
						sendStart := time.Now()
						loopSentPackets := 0
						for i := 1; i <= int(pps); i++ {
							// packetsToSend == 0 means that we need to keep sending, as there is no limit specified
							// by the user.
							if packetsToSend != 0 && runSentPackets >= packetsToSend {
								klog.Infof("%s: finished sending, sent %d packets", flow.Name, runSentPackets)
								stopFlow = true
								break
							}
							if err := handle.WritePacketData(buf.Bytes()); err != nil {
								klog.Errorf("%s cannot write packet on interface %s, %v", flow.Name, tx, err)
								return
							}
							runSentPackets += 1
							loopSentPackets += 1
						}
						klog.Infof("%s: sent %d packets (total: %d) in %s", flow.Name, loopSentPackets, runSentPackets, time.Since(sendStart))

						f.updateTx(int(sent), size)
						sleepDur := (1 * time.Second) - time.Since(sendStart)
						time.Sleep(sleepDur)
					}
				}
			}
		}

		recvFunc := func(controllerID string, stop, readyForTx chan struct{}) {
			klog.Infof("%s receive function started on interface %s", flow.Name, rx)
			ih, err := pcap.NewInactiveHandle(rx)
			if err != nil {
				klog.Errorf("cannot create handle, err: %v", err)
				return
			}
			defer ih.CleanUp()
			if err := ih.SetImmediateMode(true); err != nil {
				klog.Errorf("cannot set immediate mode on handle, err: %v", err)
				return
			}

			if err := ih.SetPromisc(true); err != nil {
				klog.Errorf("cannot set promiscous mode, err: %v", err)
				return
			}

			if err := ih.SetSnapLen(packetBytes); err != nil {
				klog.Errorf("cannot set packet length, err: %v", err)
			}

			handle, err := ih.Activate()
			if err != nil {
				klog.Errorf("%s Rx error: %v", flow.Name, err)
				return
			}
			defer handle.Close()

			ps := gopacket.NewPacketSource(handle, handle.LinkType())
			packetCh := ps.Packets()
			f := reporter.Flow(flow.Name)

			// Close the readyForTx channel so that the transmitter knows that we are ready to
			// receive packets.
			close(readyForTx)

			for {
				select {
				case <-stop:
					klog.Infof("controller ID %s, flow %s, exiting on %s", controllerID, flow.Name, rx)
					return
				case p := <-packetCh:
					if err := rxPacket(f, p, match(hdrs, p)); err != nil {
						klog.Errorf("%s cannot receive packet on interface %s, %v", flow.Name, rx, err)
					}
				}
			}
		}

		return func(tx, rx *lwotg.FlowController) {
			// Make the channel that is used for co-ordination between the sender and receiver.
			ch := make(chan struct{})
			go genFunc(tx.ID, tx.Stop, ch)
			go recvFunc(rx.ID, rx.Stop, ch)
		}, true, nil
	}
}

// Ports returns the transmit and receive ports in terms of the
// physical interfaces of the underlying system for a flow.
func Ports(flow *otg.Flow, intfs []*lwotg.OTGIntf) (tx string, rx string, err error) {
	if flow.GetTxRx() == nil || flow.GetTxRx().GetChoice() != otg.FlowTxRx_Choice_port {
		return "", "", fmt.Errorf("unsupported type of Tx/Rx specification, %v", flow.GetTxRx())
	}

	txName := flow.GetTxRx().GetPort().GetTxName()
	var rxName string
	switch rxList := flow.GetTxRx().GetPort().GetRxNames(); len(rxList) {
	case 0:
		rxName = flow.GetTxRx().GetPort().GetRxName()
		if rxName == "" {
			return "", "", fmt.Errorf("flows specified single port, but it was not specified")
		}
	case 1:
		rxName = flow.GetTxRx().GetPort().GetRxNames()[0]
	default:
		return "", "", fmt.Errorf("flows received at multiple ports are not supported, got: %d ports (%v)", len(rxList), rxList)

	}

	for _, i := range intfs {
		if i.OTGPortName == txName {
			tx = i.SystemName
		}
		if i.OTGPortName == rxName {
			rx = i.SystemName
		}
	}

	if tx == "" || rx == "" {
		return "", "", fmt.Errorf("unknown interface, tx: %q, rx: %q", tx, rx)
	}

	return tx, rx, nil
}

// Rate returns the number of packets per second that should be sent
// for the flow to meet the specified rate. The specified headers are
// used where packet size calculations are required.
//
// It returns a default rate of 1000 packets per second per the OTG
// specification if there is no rate specified.
//
// TODO(robjs): support specifications other than simple PPS.
func Rate(flow *otg.Flow, hdrs []gopacket.SerializableLayer) (uint64, error) {
	if flowT := flow.GetRate().GetChoice(); flowT != otg.FlowRate_Choice_pps && flowT != otg.FlowRate_Choice_unspecified {
		return 0, fmt.Errorf("unsupported flow rate specification, %v", flowT)
	}

	pps := flow.GetRate().GetPps()
	if pps == 0 {
		return 1000, nil
	}
	return pps, nil
}

// flowPackets returns the number of packets that should be sent for a
// particular flow. If the specification is not provided it returns 0,
// which should be interpreted as sending continuous packets.
//
// This function does not support delay or gap specifications that are
// included in OTG, and will return an error for each.
func flowPackets(flow *otg.Flow) (uint32, error) {
	if durT := flow.GetDuration().GetChoice(); durT != otg.FlowDuration_Choice_fixed_packets && durT != otg.FlowDuration_Choice_unspecified {
		return 0, fmt.Errorf("unsupported flow duration %s", durT)
	}

	// 12 is the OTG default for the packet gap.
	if (flow.GetDuration().GetFixedPackets().GetGap() != 0 && flow.GetDuration().GetFixedPackets().GetGap() != 12) || flow.GetDuration().GetFixedPackets().GetDelay() != nil {
		return 0, fmt.Errorf("gap and delay specifications are unsupported, got gap: %v, delay: %v", flow.GetDuration().GetFixedPackets().GetGap(), flow.GetDuration().GetFixedPackets().GetDelay())
	}

	return flow.GetDuration().GetFixedPackets().GetPackets(), nil
}

var (
	// timeFn is a function that returns a time.Time that can be overloaded in unit tests.
	timeFn = time.Now
)

// rxPacket is called for each packet that is received. It takes arguments of the statistics
// tracking the flow, the set of headers that are expected, and the received packet.
func rxPacket(f *counters, p gopacket.Packet, match bool) error {
	if !match {
		return nil
	}

	f.updateRx(timeFn(), len(p.Data()))
	return nil
}

// val is used to store a timestamped telemetry value.
type val struct {
	// ts is the timestamp in nanoseconds since the unix epoch that the value was
	// collected.
	ts int64
	// f is the value if it is of type float32.
	f float32
	// u is the value if it is of type uint64.
	u uint64
	// b is the value if it is of type bool.
	b bool
	// s is the value if it is of type string.
	s string
}

// stats stores metrics that are tracked for an individual flow direction.
type stats struct {
	// rate indicates the rate at which packets are being sent or received according
	// to the specific context.
	Rate *val
	// octets indicates the total number of octets that have been sent.
	Octets *val
	// pkts indicates the total number of packets that have been sent.
	Pkts *val
}
