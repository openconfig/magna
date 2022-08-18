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
	ifName = flag.String("interface", "eno1", "name of interface to use for dummy entries.")
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
		time.Sleep(5 * time.Second)
		if err := netlink.NeighAdd(fakeNeigh); err != nil {
			rErr = err
			return
		}
	}()

	mac, err := intf.AwaitARP(ctx, net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatalf("cannot create subscription, %v", err)
	}

	if !cmp.Equal(mac, m) {
		t.Fatalf("did not get expected MAC, got: %v, want: %v", mac, m)
	}

	if rErr != nil {
		t.Fatalf("error occurred in adding entry, %v", err)
	}

	if err := netlink.NeighDel(fakeNeigh); err != nil {
		t.Fatalf("cannot delete fake neighbour, %v", err)
	}
}
