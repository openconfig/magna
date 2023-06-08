package arp

import (
	"fmt"
	"net"
	"testing"

	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/magna/intf"
	"github.com/openconfig/magna/lwotgtelem"
	"github.com/openconfig/magna/otgyang"
	"github.com/openconfig/ygot/testutil"
	"github.com/openconfig/ygot/ygot"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

func TestNeighUpdates(t *testing.T) {
	tests := []struct {
		desc              string
		inTarget          string
		inHintFn          func() lwotgtelem.HintMap
		inTimeFn          func() int64
		inListFn          func() ([]*intf.ARPEntry, error)
		wantNotifications []*gpb.Notification
		wantErrSubstring  string
	}{{
		desc:     "error listing ARP neighbours",
		inTarget: "dut",
		inHintFn: func() lwotgtelem.HintMap {
			return lwotgtelem.HintMap{}
		},
		inTimeFn: func() int64 {
			return int64(42)
		},
		inListFn: func() ([]*intf.ARPEntry, error) {
			return nil, fmt.Errorf("cannot get neighbours")
		},
		wantErrSubstring: "cannot list ARP neighbours",
	}, {
		desc:     "no valid hints",
		inTarget: "dut",
		inHintFn: func() lwotgtelem.HintMap {
			return lwotgtelem.HintMap{"fish": map[string]string{}}
		},
		inTimeFn: func() int64 {
			return int64(42)
		},
		inListFn: func() ([]*intf.ARPEntry, error) {
			return []*intf.ARPEntry{}, nil
		},
		wantErrSubstring: "cannot map with nil interface mapping table",
	}, {
		desc:     "single mappable interface",
		inTarget: "dut",
		inHintFn: func() lwotgtelem.HintMap {
			return lwotgtelem.HintMap{
				interfaceMapHintName: map[string]string{
					"eth0": "ETHERNET42",
				},
			}
		},
		inTimeFn: func() int64 { return 42 },
		inListFn: func() ([]*intf.ARPEntry, error) {
			myMAC, err := net.ParseMAC("00:00:5e:00:53:01")
			if err != nil {
				t.Fatalf("cannot parse MAC, %v", err)
			}

			theirMAC, err := net.ParseMAC("00:00:ff:ff:42:42")
			if err != nil {
				t.Fatalf("cannot parse remote MAC, %v", err)
			}

			return []*intf.ARPEntry{{
				IP: net.IP{192, 0, 2, 1},
				Interface: &intf.Interface{
					Index: 1,
					Name:  "eth0",
					MAC:   myMAC,
				},
				MAC: theirMAC,
			}}, nil
		},
		wantNotifications: func() []*gpb.Notification {
			s := &otgyang.Device{}
			n := s.GetOrCreateInterface("ETHERNET42").GetOrCreateIpv4Neighbor("192.0.2.1")
			n.LinkLayerAddress = ygot.String("00:00:ff:ff:42:42")
			g, err := ygot.TogNMINotifications(s, 42, ygot.GNMINotificationsConfig{UsePathElem: true})
			if err != nil {
				t.Fatalf("cannot generate notifications, got err: %v", err)
			}
			if len(g) != 1 {
				t.Fatalf("did not get expected notification length, got: %d, want: 1", len(g))
			}
			g[0].Prefix = &gpb.Path{Target: "dut", Origin: "openconfig"}
			return g
		}(),
	}}

	for _, tt := range tests {
		arpListFn = intf.ARPList

		t.Run(tt.desc, func(t *testing.T) {
			arpListFn = tt.inListFn
			got, err := neighUpdates(tt.inTarget, tt.inHintFn, tt.inTimeFn)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error, diff: %s", diff)
			}

			if !testutil.NotificationSetEqual(got, tt.wantNotifications) {
				t.Fatalf("did not get expected notification set. got:\n%s\n, want:\n%s\n", got, tt.wantNotifications)
			}
		})
	}
}
