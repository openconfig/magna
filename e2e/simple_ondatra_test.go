package simple_ondatra_test

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/topologies/binding"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"

	mpb "github.com/openconfig/magna/proto/mirror"
)

const (
	// destinationLabel is the outer label that is used for the generated packets in MPLS flows.
	destinationLabel = 100
	// innerLabel is the inner label used for the generated packets in MPLS flows.
	innerLabel = 5000
)

var (
	// sleepTime allows a user to specify that the test should sleep after setting
	// up all elements (configuration, gRIBI forwarding entries, traffic flows etc.).
	sleepTime = flag.Duration("sleep", 10*time.Second, "duration for which the test should sleep after setup")
)

// intf is a simple description of an interface.
type intf struct {
	// Name is the name of the interface.
	Name string
	// MAC is the MAC address for the interface.
	MAC string
}

var (
	// ateSrc describes the configuration parameters for the ATE port sourcing
	// a flow.
	ateSrc = &intf{
		Name: "port1",
		MAC:  "02:00:01:01:01:01",
	}

	ateDst = &intf{
		Name: "port2",
		MAC:  "02:00:02:01:01:01",
	}
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, binding.New)
}

// configureATE interfaces configrues the source and destination ports on ATE according to the specifications
// above. It returns the OTG configuration object.
func configureATEInterfaces(t *testing.T, ate *ondatra.ATEDevice, srcATE, dstATE *intf) (gosnappi.Config, error) {
	otg := ate.OTG()
	topology := otg.NewConfig(t)
	for _, p := range []*intf{ateSrc, ateDst} {
		topology.Ports().Add().SetName(p.Name)
		dev := topology.Devices().Add().SetName(p.Name)
		eth := dev.Ethernets().Add().SetName(fmt.Sprintf("%s_ETH", p.Name))
		eth.SetPortName(dev.Name()).SetMac(p.MAC)
	}

	c, err := topology.ToJson()
	if err != nil {
		return topology, err
	}
	t.Logf("configuration for OTG is %s", c)

	otg.PushConfig(t, topology)
	return topology, nil
}

// pushBaseConfigs pushes the base configuration to the ATE and DUT devices in
// the test topology.
func pushBaseConfigs(t *testing.T, ate *ondatra.ATEDevice) gosnappi.Config {
	otgCfg, err := configureATEInterfaces(t, ate, ateSrc, ateDst)
	if err != nil {
		t.Fatalf("cannot configure ATE interfaces via OTG, %v", err)
	}

	return otgCfg
}

// TestMPLS is a simple test that creates an MPLS flow between two ATE ports and
// checks that there is no packet loss. It validates magna's end-to-end MPLS
// flow accounting.
func TestMPLS(t *testing.T) {
	ate := ondatra.ATE(t, "ate")
	sr := &mpb.StartRequest{
		From: ate.Port(t, "port1").Name(),
		To:   ate.Port(t, "port2").Name(),
	}

	dut := ondatra.DUT(t, "mirror")
	_ = dut

	fmt.Printf("%s\n", sr)

	otgCfg := pushBaseConfigs(t, ondatra.ATE(t, "ate"))

	otg := ondatra.ATE(t, "ate").OTG()
	otgCfg.Flows().Clear().Items()
	mplsFlow := otgCfg.Flows().Add().SetName("MPLS_FLOW")
	mplsFlow.Metrics().SetEnable(true)
	mplsFlow.TxRx().Port().SetTxName(ateSrc.Name).SetRxName(ateDst.Name)

	mplsFlow.Rate().SetChoice("pps").SetPps(1)

	// Set up ethernet layer.
	eth := mplsFlow.Packet().Add().Ethernet()
	eth.Src().SetChoice("value").SetValue(ateSrc.MAC)
	eth.Dst().SetChoice("value").SetValue(ateDst.MAC)

	// Set up MPLS layer with destination label.
	mpls := mplsFlow.Packet().Add().Mpls()
	mpls.Label().SetChoice("value").SetValue(destinationLabel)
	mpls.BottomOfStack().SetChoice("value").SetValue(0)

	mplsInner := mplsFlow.Packet().Add().Mpls()
	mplsInner.Label().SetChoice("value").SetValue(innerLabel)
	mplsInner.BottomOfStack().SetChoice("value").SetValue(1)

	otg.PushConfig(t, otgCfg)

	t.Logf("Starting MPLS traffic...")
	otg.StartTraffic(t)
	t.Logf("Sleeping for %s...", *sleepTime)
	time.Sleep(*sleepTime)
	t.Logf("Stopping MPLS traffic...")
	otg.StopTraffic(t)

	metrics := gnmi.Get(t, otg, gnmi.OTG().Flow("MPLS_FLOW").State())
	got, want := metrics.GetCounters().GetInPkts(), metrics.GetCounters().GetOutPkts()
	lossPackets := want - got
	if lossPackets != 0 {
		t.Fatalf("did not get expected number of packets, got: %d, want: %d", got, want)
	}
}
