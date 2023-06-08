// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intf

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"k8s.io/klog"
)

const (
	// RTM_NEWNEIGH is the event sent from netlink when an ARP entry is added.
	RTM_NEWNEIGH uint16 = 28
	// RTM_DELNEIGH is the event sent from netlink when an ARP entry is removed.
	RTM_DELNEIGH uint16 = 29
)

func init() {
	// On init when the package has been built on Linux, load the netlink
	// accessor as the implementation to be used.
	//
	// TODO(robjs): Consider whether we should use build tags vs. solely
	// the underlying system, since this would allow a build tag to say
	// that the package should use gRPC wire.
	klog.Infof("Initialising with Linux profile.")
	accessor = netlinkAccessor{}
}

// netlinkAccessor implements the NetworkAccessor interface for a Linux
// system.
type netlinkAccessor struct {
	unimplementedAccessor
}

// Interface retrieves the interface named from the underlying system
// through making a netlink call.
func (n netlinkAccessor) Interface(name string) (*Interface, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("cannot get interface %s, %v", name, err)
	}

	attrs := link.Attrs()
	return &Interface{
		Index: attrs.Index,
		Name:  attrs.Name,
		MAC:   attrs.HardwareAddr,
	}, nil
}

// Interfaces retrieves the list of interfaces on the local system and returns them as a
// parsed set of interfaces.
func (n netlinkAccessor) Interfaces() ([]*Interface, error) {
	ints, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("cannot list interfaces, %v", err)
	}

	intfs := []*Interface{}
	for _, i := range ints {
		attrs := i.Attrs()
		intfs = append(intfs, &Interface{
			Index: attrs.Index,
			Name:  attrs.Name,
			MAC:   attrs.HardwareAddr,
		})
	}
	return intfs, nil
}

// interfaceByIndex retrieves an interface based on its underlying netlink index.
func interfaceByIndex(idx int) (*Interface, error) {
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return nil, fmt.Errorf("cannot find link by index %d", idx)
	}
	return &Interface{
		Index: idx,
		Name:  link.Attrs().Name,
		MAC:   link.Attrs().HardwareAddr,
	}, nil
}

// InterfaceAddresses retrieves the set of addresses that are configured on interface
// name. It returns the addresses as a set of net.IPNet structs including the address
// and mask of each interface.
func (n netlinkAccessor) InterfaceAddresses(name string) ([]*net.IPNet, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("cannot get interface, %v", err)
	}
	addrs, err := netlink.AddrList(link, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve interface %s addresses, %v", name, err)
	}

	nets := []*net.IPNet{}
	for _, a := range addrs {
		nets = append(nets, a.IPNet)
	}
	return nets, nil
}

// AddInterfaceIP adds the address addr to the interface name using netlink.
func (n netlinkAccessor) AddInterfaceIP(name string, addr *net.IPNet) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("cannot get interface, %v", err)
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: addr}); err != nil {
		return fmt.Errorf("cannot add IP address to interface %s, %v", name, err)
	}
	return nil
}

// ARPList lists the current entries in the ARP table of the system and returns them
// as parsed out ARPEntry structs. It uses the netlink neighbour list as a data source.
func (n netlinkAccessor) ARPList() ([]*ARPEntry, error) {
	neighs, err := netlink.NeighList(0, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve ARP list, %v", err)
	}

	entries := []*ARPEntry{}
	for _, n := range neighs {
		intf, err := interfaceByIndex(n.LinkIndex)
		if err != nil {
			return nil, fmt.Errorf("cannot find link for neighbour %v, err: %v", n, err)
		}
		entries = append(entries, &ARPEntry{
			IP:        n.IP,
			MAC:       n.HardwareAddr,
			Interface: intf,
		})
	}
	return entries, nil
}

// ARPSubscribe makes a subscription to the netlink ARP table and writes the results
// that are returned to the updates channel as ARPUpdate messages. The done channel is
// used to cancel the subscription which is spawned in a separate goroutine.
func (n netlinkAccessor) ARPSubscribe(updates chan ARPUpdate, done chan struct{}) error {
	nlUpdates := make(chan netlink.NeighUpdate)

	go func() {
		for {
			select {
			case upd := <-nlUpdates:
				u := ARPUpdate{
					Type: ARPUnknown,
					Neigh: ARPEntry{
						IP:  upd.Neigh.IP,
						MAC: upd.Neigh.HardwareAddr,
					},
				}
				switch upd.Type {
				case RTM_NEWNEIGH:
					u.Type = ARPAdd
				case RTM_DELNEIGH:
					u.Type = ARPDelete
				}

				// TODO(robjs): Determine what to do here, since this is an internal
				// error from netlink. We can ignore it for the moment since it meant
				// that an interface went away during our subscription.
				intf, _ := interfaceByIndex(upd.Neigh.LinkIndex)
				u.Neigh.Interface = intf
				updates <- u
			case <-done:
				return
			}
		}
	}()

	if err := netlink.NeighSubscribe(nlUpdates, done); err != nil {
		return fmt.Errorf("cannot subscribe to neighbours, err: %v", err)
	}

	return nil
}
