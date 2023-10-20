package simple_ondatra_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
)

func TestScaleMPLS(t *testing.T) {

	tests := []struct {
		desc                string
		inFlowCount         int
		inPPS               uint64
		inLossTolerance     uint64
		inNumPacketsPerFlow uint32
	}{{
		desc:            "10 flows, 1 pps",
		inFlowCount:     10,
		inPPS:           1,
		inLossTolerance: 1,
	}, {
		desc:                "10 flows, 1 pps, 5 packets",
		inFlowCount:         10,
		inPPS:               1,
		inNumPacketsPerFlow: 5,
	}, {
		desc:            "1 flow, 10 pps",
		inFlowCount:     1,
		inPPS:           10,
		inLossTolerance: 1,
	}, {
		desc:                "1 flow, 100 pps",
		inFlowCount:         1,
		inPPS:               100,
		inNumPacketsPerFlow: 800, // send for 8 seconds.
	}, {
		desc:                "10 flows, 10 pps",
		inFlowCount:         10,
		inPPS:               10,
		inNumPacketsPerFlow: 50, // send for 5 seconds
	}, {
		desc:                "100 flows, 10 pps",
		inFlowCount:         100,
		inPPS:               10,
		inNumPacketsPerFlow: 20, // send for 2 seconds
	}, {
		desc:                "1 flow, 600 pps",
		inFlowCount:         1,
		inPPS:               600,
		inNumPacketsPerFlow: 1800, // run for 3 seconds
	}, {
		desc:                "1 flow, 1000 pps",
		inFlowCount:         1,
		inPPS:               1000,
		inNumPacketsPerFlow: 5 * 1000, // run for 5 seconds
	}, {
		desc:                "100 flows",
		inFlowCount:         100,
		inPPS:               1,
		inNumPacketsPerFlow: 6, // send for 6 seconds
	}, {
		desc:                "254 flows, 1 pps",
		inFlowCount:         254,
		inPPS:               1,
		inNumPacketsPerFlow: 5, // send for 5 seconds
		/*
				Currently beyond the scale limit.
			}, {
				desc:                "254 flows, 10 pps",
				inFlowCount:         254,
				inPPS:               10,
				inNumPacketsPerFlow: 20, // send for 2 seconds
		*/
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			// Start a mirroring session to copy packets.
			maddr := mirrorAddr(t)
			client, stop := mirrorClient(t, maddr)
			defer stop()
			startTwoPortMirror(t, client)
			time.Sleep(1 * time.Second)
			defer func() { stopTwoPortMirror(t, client) }()

			otgCfg := pushBaseConfigs(t, ondatra.ATE(t, "ate"))

			otg := ondatra.ATE(t, "ate").OTG()
			otgCfg.Flows().Clear().Items()
			for i := 0; i < tt.inFlowCount; i++ {
				addMPLSFlow(t, otgCfg, fmt.Sprintf("flow%d", i), ateSrc.Name, ateDst.Name, fmt.Sprintf("100.64.%d.1", i), fmt.Sprintf("100.64.%d.2", i), tt.inPPS, tt.inNumPacketsPerFlow)
			}

			otg.PushConfig(t, otgCfg)

			t.Logf("Starting MPLS traffic...")
			otg.StartTraffic(t)
			t.Logf("Sleeping for %s...", *sleepTime)
			time.Sleep(*sleepTime)
			t.Logf("Stopping MPLS traffic...")
			otg.StopTraffic(t)

			// Avoid a race with telemetry updates.
			time.Sleep(2 * time.Second)
			for i := 0; i < tt.inFlowCount; i++ {
				metrics := gnmi.Get(t, otg, gnmi.OTG().Flow(fmt.Sprintf("flow%d", i)).State())
				got, want := metrics.GetCounters().GetInPkts(), metrics.GetCounters().GetOutPkts()
				t.Logf("flow %d: sent: %d, recv: %d", i, want, got)
				if lossPackets := want - got; lossPackets > tt.inLossTolerance {
					t.Errorf("flow %d: did not get expected number of packets, got: %d, want: %d", i, got, want)
				}
			}
		})
	}
}
