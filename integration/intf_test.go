// Package integration contains integration tests for the magna package.
package integration

import (
	"context"
	"flag"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/magna/intf"
	"github.com/vishvananda/netlink"
)

var (
	ifName = flag.String("interface", "eth0", "name of interface to use for dummy entries.")
)

func TestNeighSubscribe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	locInt, err := intf.InterfaceByName(*ifName)
	if err != nil {
		t.Fatalf("cannot find specified interface %s", *ifName)
	}

	m, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		t.Fatalf("cannot parse MAC, %v", err)
	}

	fakeNeigh := &netlink.Neigh{
		Family:       netlink.FAMILY_V4,
		LinkIndex:    locInt.Index,
		IP:           net.ParseIP("192.0.2.1"),
		State:        netlink.NUD_PERMANENT,
		HardwareAddr: m,
	}

	var rErr error
	go func() {
		time.Sleep(2 * time.Second)
		if err := netlink.NeighAdd(fakeNeigh); err != nil {
			// Cancel the context, subsequent calls will fail.
			cancel()
			rErr = err
			return
		}
	}()

	mac, err := intf.AwaitARP(ctx, net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Errorf("cannot create subscription, %v", err)
	}

	if !cmp.Equal(mac, m) {
		t.Errorf("did not get expected MAC, got: %v, want: %v", mac, m)
	}

	if rErr != nil {
		t.Errorf("did not set ARP neighbour, got err: %v", err)
	}

	if err := netlink.NeighDel(fakeNeigh); err != nil {
		t.Fatalf("cannot delete fake neighbour, %v", err)
	}
}

func TestInterfaces(t *testing.T) {
	ints, err := intf.Interfaces()
	if err != nil {
		t.Fatalf("cannot retrieve interfaces, err: %v", err)
	}

	if len(ints) == 0 {
		t.Fatalf("zero interfaces returned, %v", ints)
	}

	t.Logf("Got interfaces: %v", ints)
}
