// Package common providers common OTG flow helper functions.
package common

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"github.com/openconfig/magna/lwotg"
)

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
