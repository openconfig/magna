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

// Package intf implements mechanisms to access underlying interfaces in
// a manner that is agnostic to the underlying implementation. An implementation
// is included that uses netlink to write to a Linux kernl implementation.
// Additional implementations can be provided to allow writing to e.g. a
// gRPCwire implementation.
package intf

import (
	"context"
	"fmt"
	"net"
)

// Interface represents information corresponding to a single interface on the
// underlying system.
type Interface struct {
	// Index is an integer index used to refer to the interface.
	Index int
	// Name is the name used to refer to the interface in the system.
	Name string
	// MAC is the MAC address of the interface.
	MAC net.HardwareAddr
}

// String is the string representation of an interface that can be read by humans.
func (i Interface) String() string {
	return fmt.Sprintf("%s (index %d, MAC: %s)", i.Name, i.Index, i.MAC)
}

// ARPEntry is a representation of an ARP entry on the underlying system.
type ARPEntry struct {
	// IP is the IP address of the neighbour.
	IP net.IP
	// Interface is the name of the interface on which the ARP entry was learnt.
	Interface *Interface
	// MAC is the MAC address of the neighbour.
	MAC net.HardwareAddr
}

// ARPEvent is used to describe a particular event on the ARP table.
type ARPEvent int64

const (
	// ARPUnknown is used when the event is not an add or delete.
	ARPUnknown ARPEvent = iota
	// ARPAdd indicates that the ARP neighbour was added.
	ARPAdd
	// ARPDelete inidcates that the ARP neighbour was deleted.
	ARPDelete
)

// ARPUpdate is used to describe a change to the ARP table.
type ARPUpdate struct {
	// Type indicates whether the event was an add or delete.
	Type ARPEvent
	// Neigh is the neighbour that the change corresponds to.
	Neigh ARPEntry
}

// NetworkAccessor is an interface implemented by the underlying system access
// interface. Through implementing the NetworkAccessor interface it is possible
// to use the functions within this package whilst using a different underlying
// implementation (e.g., netlink on Linux to access the kernel).
type NetworkAccessor interface {
	// Interfaces returns a set of interfaces that are present on the local system.
	Interfaces() ([]*Interface, error)
	// Interface retrieves the interface with the specified name.
	Interface(name string) (*Interface, error)
	// InterfaceAdddresses lists the IP addresses configured on a particular interface.
	InterfaceAddresses(name string) ([]*net.IPNet, error)
	// AddInterfaceIP adds address ip to the interface name.
	AddInterfaceIP(name string, ip *net.IPNet) error
	// ARPList lists the set of ARP neighbours on the system.
	ARPList() ([]*ARPEntry, error)
	// ARPSubscribe writes changes to the ARP table to the channel updates, and uses
	// done to indicate that the subscription is complete. The ARPSubscribe function
	// should not be blocking and rather return once it has started a separate goroutine
	// that writes updates to the updates channel, and can be cancelled by sending a
	// message to the done channel.
	ARPSubscribe(updates chan ARPUpdate, done chan struct{}) error
}

// unimplementedAccessor is an accessor interface that returns unimplemented
// for all underlying methods.
type unimplementedAccessor struct{}

// Interface returns unimplemented for the interface call.
func (u unimplementedAccessor) Interface(_ string) (*Interface, error) {
	return nil, fmt.Errorf("unimplemented Interface method")
}

// Interfaces returns unimplemented when asked to list interfaces.
func (u unimplementedAccessor) Interfaces() ([]*Interface, error) {
	return nil, fmt.Errorf("unimplemented Interfaces method")
}

// InterfaceAddresses returns unimplemented when asked for list IP addresses.
func (u unimplementedAccessor) InterfaceAddresses(_ string) ([]*net.IPNet, error) {
	return nil, fmt.Errorf("unimplemented InterfaceAddresses method")
}

// AddInterfaceIP returns unimplemented when asked to add an interface.
func (u unimplementedAccessor) AddInterfaceIP(_ string, _ *net.IPNet) error {
	return fmt.Errorf("unimplemented AddInterfaceIP method")
}

// ARPList returns unimplemented when asked to list ARP entries.
func (u unimplementedAccessor) ARPList() ([]*ARPEntry, error) {
	return nil, fmt.Errorf("unimplemented ARPList method")
}

// ARPSubscribe returns unimplemented when asked to subscribe to ARP changes.
func (u unimplementedAccessor) ARPSubscribe(_ chan ARPUpdate, _ chan struct{}) error {
	return fmt.Errorf("unimplemented ARPSubscribe method")
}

// accessor is the implementation of the network accessor that should be used. It
// should be set by init() [which may be a platform-specific initiation].
var accessor NetworkAccessor

// InterfaceByName returns an interface's attributes  by the name of the interface.
func InterfaceByName(name string) (*Interface, error) {
	return accessor.Interface(name)
}

// ValidInterface determines whether the interface name is valid for the
// current system.
func ValidInterface(name string) bool {
	if accessor == nil {
		panic("accessor was nil, this package was not built on a supported system.")
	}
	if _, err := accessor.Interface(name); err != nil {
		return false
	}
	return true
}

// AddIP adds an IP address addr to the interface intf.
func AddIP(intf string, addr *net.IPNet) error {
	addrs, err := accessor.InterfaceAddresses(intf)
	if err != nil {
		return fmt.Errorf("cannot determine interface addresses, %v", err)
	}

	for _, a := range addrs {
		if a.IP.Equal(addr.IP) {
			return nil // already configured.
		}
	}

	// Configure the address.
	if err := accessor.AddInterfaceIP(intf, addr); err != nil {
		return fmt.Errorf("cannot add address, %v", err)
	}
	return nil
}

// AwaitARP waits for the IPv4 address addr to be resolved via ARP. It uses the supplied
// context to determine whether it should continue awaiting the entry. If the ARP entry
// is resolved, it is returned directly.
func AwaitARP(ctx context.Context, addr net.IP) (net.HardwareAddr, error) {
	neighs, err := accessor.ARPList()
	if err != nil {
		return nil, fmt.Errorf("cannot retrieve list of ARP entries, %v", err)
	}

	for _, n := range neighs {
		if addr.Equal(n.IP) {
			return n.MAC, nil
		}
	}

	updates := make(chan ARPUpdate, 1)
	result := make(chan ARPUpdate, 1)

	go func() {
		for {
			upd := <-updates
			if upd.Type == ARPAdd {
				if addr.Equal(upd.Neigh.IP) {
					result <- upd
					// We only care about the first ARP update, so return
					// when we have received an initial update.
					return
				}
			}
		}
	}()

	done := make(chan struct{})
	if err := accessor.ARPSubscribe(updates, done); err != nil {
		return nil, fmt.Errorf("cannot subscribe to ARP updates, err: %v", err)
	}

	select {
	case n := <-result:
		done <- struct{}{}
		return n.Neigh.MAC, nil
	case <-ctx.Done():
		done <- struct{}{}
		return nil, ctx.Err()
	}
}

// ARPList returns a list of ARP neighbours.
func ARPList() ([]*ARPEntry, error) {
	return accessor.ARPList()
}

// ARPSubscribe subscribes to ARP updates from the underlying accessor.
func ARPSubscribe(updates chan ARPUpdate, done chan struct{}) error {
	return accessor.ARPSubscribe(updates, done)
}

// Interfaces returns a list of interfaces from the local system.
func Interfaces() ([]*Interface, error) {
	return accessor.Interfaces()
}
