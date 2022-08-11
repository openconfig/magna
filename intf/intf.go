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
	"fmt"
	"net"
)

// Link represents information corresponding to a single interface on the
// underlying system.
type Interface struct {
	// Index is an integer index used to refer to the interface.
	Index int
	// Name is the name used to refer to the interface in the system.
	Name string
	// MAC is the MAC address of the interface.
	MAC net.HardwareAddr
}

// ARPNeigh is a representation of an ARP entry on the underlying system.
type ARPNeigh struct {
	// IP is the IP address of the neighbour.
	IP net.IP
	// Interface is the name of the interface on which the ARP entry was learnt.
	Interface string
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
	// Neigh is the neighbour that the change corresponds to
	Neigh ARPNeigh
}

// NetworkAccessor is an interface implemented by the underlying system access
// interface. Through implementing the NetworkAccessor interface it is possible
// to use the functions within this package whilst using a different underlying
// implementation (e.g., netlink on Linux to access the kernel).
type NetworkAccessor interface {
	// Links returns a set of links that are present on the local system.
	Interfaces() ([]*Interface, error)
	// Link retrieves the link with the specified name.
	Interface(name string) (*Interface, error)
	// AddressList lists the IP addresses configured on a particular interface.
	InterfaceAddresses(name string) ([]*net.IPNet, error)
	// AddressAdd adds address ip to the interface name.
	AddInterfaceIP(name string, ip *net.IPNet) error
	// ARPList lists the set of ARP neighbours on the system.
	ARPList() ([]*ARPNeigh, error)
	// ARPSubscribe writes changes to the ARP table to the channel updates, and uses
	// done to indicate that the subscription is complete.
	ARPSubscribe(updates chan ARPUpdate, done chan struct{}) error
}

// unimplementedAccessor is an accessor interface that returns unimplemented
// for all underlying methods.
type unimplementedAccessor struct{}

// Interface returns unimplemented for the interface call.
func (u unimplementedAccessor) Interface(_ string) (*Interface, error) {
	return nil, fmt.Errorf("unimplemented")
}

// Interfaces returns unimplemented when asked to list interfaces.
func (n unimplementedAccessor) Interfaces() ([]*Interface, error) {
	return nil, fmt.Errorf("unimplemented")
}

// InterfaceAddresses returns unimplemented when asked for list IP addresses.
func (n unimplementedAccessor) InterfaceAddresses(_ string) ([]*net.IPNet, error) {
	return nil, fmt.Errorf("unimplemented")
}

// AddInterfaceIP returns unimplemented when asked to add an interface.
func (n unimplementedAccessor) AddInterfaceIP(_ string, _ *net.IPNet) error {
	return fmt.Errorf("unimplemented")
}

// ARPList returns unimplemented when asked to list ARP entries.
func (n unimplementedAccessor) ARPList() ([]*ARPNeigh, error) {
	return nil, fmt.Errorf("unimplemented")
}

// ARPSubscribe returns unimplemented when asked to subscribe to ARP changes.
func (n unimplementedAccessor) ARPSubscribe(_ chan ARPUpdate, _ chan struct{}) error {
	return fmt.Errorf("unimplemented")
}

// accessor is the implementation of the network accessor that should be used. It
// should be set by init() [which may be a platform-specific initiation].
var accessor NetworkAccessor

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
		return err
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
