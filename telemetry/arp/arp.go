package arp

import (
	"context"
	"fmt"
	"net"

	"github.com/openconfig/lemming/gnmi/gnmit"
	"github.com/openconfig/magna/intf"
	"github.com/openconfig/magna/lwotgtelem"
	"github.com/openconfig/magna/otgyang"
	"github.com/openconfig/magna/telemetry/common"
	"github.com/openconfig/ygot/ygot"
	"k8s.io/klog"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	// interfaceMapHintName is the name used for the map of interface names
	// in the telemetry hint channel.
	interfaceMapHintName = "interface_map"
)

// arpUpdate generates a gNMI Update for the IPv4 ARP neighbour specified by the hardware
// address and IP on the link specified. It returns a populated gNMI Notification.
func arpUpdate(h net.HardwareAddr, ip net.IP, link, target string, timeFn func() int64) (*gpb.Notification, error) {
	s := &otgyang.Device{}
	n := s.GetOrCreateInterface(link).GetOrCreateIpv4Neighbor(ip.String())
	n.LinkLayerAddress = ygot.String(h.String())

	g, err := ygot.TogNMINotifications(s, timeFn(), ygot.GNMINotificationsConfig{UsePathElem: true})
	if err != nil {
		klog.Errorf("cannot serialise gNMI Notifications, %v", err)
	}
	return common.AddTarget(g[0], target), nil
}

// arpListFn define s afunction that can be used to get the current set of ARP neighbours. It can be
// overridden in unit tests to allow internals of the ARP telemetry to be tested.
var arpListFn = intf.ARPList

// neighUpdates generates telemetry updates for the ARP neighbours that are in the current ARP
// cache on the target. It uses the specified target name in the update, and retrieves the mapping
// of interface names from the specified hintFn. The timeFn is used to populate the timestamp
// within the gNMI Notification. It returns a slice of gNMI Notifications that are to be sent
// as telemetry updates. It does not take into account any diff in the ARP cache.
func neighUpdates(target string, hintFn func() lwotgtelem.HintMap, timeFn func() int64) ([]*gpb.Notification, error) {
	neighs, err := arpListFn()
	if err != nil {
		return nil, fmt.Errorf("cannot list ARP neighbours, %v", err)
	}
	klog.Infof("ARPList returned %v", neighs)

	hints := hintFn()
	klog.Infof("got hints, %v", hints)
	if _, ok := hints[interfaceMapHintName]; !ok {
		klog.Errorf("no valid hints, %v", hints)
		return nil, fmt.Errorf("arpNeighbors: cannot map with nil interface mapping table.")
	}

	upds := []*gpb.Notification{}
	for _, n := range neighs {
		linkName := hints[interfaceMapHintName][n.Interface.Name]
		if linkName == "" {
			continue
		}
		if n.IP.To4() == nil {
			continue
		}
		u, err := arpUpdate(n.MAC, n.IP, linkName, target, timeFn)
		if err != nil {
			return nil, fmt.Errorf("cannot generate notification for %s (%s), %v", n.MAC, n.IP, err)
		}
		klog.Infof("enqueuing telemetry update, %v", u)
		upds = append(upds, u)
	}
	return upds, nil
}

// New returns a new gnmit Task that provides telemetry updates on the ARP cache.
func New(ctx context.Context, hintFn func() lwotgtelem.HintMap, timeFn func() int64) gnmit.Task {
	arpTask := func(_ gnmit.Queue, updateFn gnmit.UpdateFn, target string, cleanup func()) error {
		var retErr error
		go func() {
			upds, err := neighUpdates(target, hintFn, timeFn)
			switch err {
			case nil:
				klog.Infof("updates to send %v", upds)
				for _, u := range upds {
					klog.Infof("sending ARP gNMI update %s", u)
					updateFn(u)
				}
			default:
				klog.Errorf("could not get updates for initial sync, %v", err)
			}

			ch := make(chan intf.ARPUpdate, 100)
			doneCh := make(chan struct{})
			if err := intf.ARPSubscribe(ch, doneCh); err != nil {
				klog.Infof("error opening ARP channel, %v", err)
				retErr = fmt.Errorf("cannot open ARP update channel, %v", err)
				return
			}

			for {
				select {
				case <-ctx.Done():
					doneCh <- struct{}{}
				case u := <-ch:
					klog.Infof("received an ARP update, %V", u)
					hints := hintFn()
					linkName := hints[interfaceMapHintName][u.Neigh.Interface.Name]

					upds, err := neighUpdates(target, hintFn, timeFn)
					switch err {
					case nil:
						for _, u := range upds {
							updateFn(u)
						}
					default:
						klog.Errorf("cannot generate ARP updates, %v", err)
					}

					if linkName != "" {
						u, err := arpUpdate(u.Neigh.MAC, u.Neigh.IP, linkName, target, timeFn)
						if err != nil {
							klog.Errorf("got error generating update, %v", err)
						}
						if err := updateFn(u); err != nil {
							klog.Errorf("got error sending ARP update, %v", err)
						}
					}
				}
			}
		}()

		return retErr
	}

	klog.Infof("returning ARP task...")
	return gnmit.Task{Run: arpTask}
}
