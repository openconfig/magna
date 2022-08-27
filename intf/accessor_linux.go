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
)

func init() {
	// On init when the package has been built on Linux, load the netlink
	// accessor as the implementation to be used.
	//
	// TODO(robjs): Consider whether we should use build tags vs. solely
	// the underlying system, since this would allow a build tag to say
	// that the package should use gRPC wire.
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

// InterfaceAddIP adds the address addr to the interface name using netlink.
func (n netlinkAccessor) InterfaceAddIP(name string, addr *net.IPNet) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("cannot get interface, %v", err)
	}
	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: addr}); err != nil {
		return fmt.Errorf("cannot add IP address to interface %s, %v", name, err)
	}
	return nil
}
