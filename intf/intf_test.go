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
	"testing"
)

type validInterfaceAccessor struct {
	unimplementedAccessor
}

func (validInterfaceAccessor) Interface(name string) (*Interface, error) {
	switch name {
	case "eth0":
		return &Interface{}, nil
	case "eth42":
		return &Interface{}, fmt.Errorf("error")
	}
	return nil, fmt.Errorf("does not exist")
}

func TestValidInterface(t *testing.T) {
	oldAccessor := accessor
	defer func() {
		accessor = oldAccessor
	}()
	accessor = validInterfaceAccessor{}

	tests := []struct {
		name string
		in   string
		want bool
	}{{
		name: "exists",
		in:   "eth0",
		want: true,
	}, {
		name: "does not exist",
		in:   "eth42",
		want: false,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := ValidInterface(tt.in), tt.want; got != want {
				t.Fatalf("InterfaceValid(%s), did not get expected interface valid response, got: %v, want: %v", tt.in, got, want)
			}
		})
	}
}

type addIPAccessor struct {
	unimplementedAccessor
}

func (addIPAccessor) InterfaceAddresses(name string) ([]*net.IPNet, error) {
	switch name {
	case "no-addresses":
		return nil, nil
	case "one-address", "add-fails":
		return []*net.IPNet{
			{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(30, 32)},
		}, nil
	case "two-addresses":
		return []*net.IPNet{
			{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(30, 32)},
			{IP: net.ParseIP("192.0.2.5"), Mask: net.CIDRMask(30, 32)},
		}, nil
	default:
		return nil, fmt.Errorf("unknown interface %s", name)
	}
}

func (addIPAccessor) AddInterfaceIP(intf string, _ *net.IPNet) error {
	switch intf {
	case "no-addresses", "one-address":
		return nil
	case "add-fails":
		return fmt.Errorf("add IP failed")
	default:
		return fmt.Errorf("unknown interface")
	}
}

func TestAddIP(t *testing.T) {
	oldAccessor := accessor
	defer func() {
		accessor = oldAccessor
	}()
	accessor = addIPAccessor{}

	tests := []struct {
		name        string
		inInterface string
		inAddress   *net.IPNet
		wantErr     bool
	}{{
		name:        "add interface to interface with no addresses",
		inInterface: "no-addresses",
		inAddress:   &net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(31, 32)},
	}, {
		name:        "add existing address",
		inInterface: "one-address",
		inAddress:   &net.IPNet{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(30, 32)},
	}, {
		name:        "unknown interface",
		inInterface: "does-not-exist",
		wantErr:     true,
	}, {
		name:        "add IP fails",
		inInterface: "add fails",
		wantErr:     true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := accessor.AddInterfaceIP(tt.inInterface, tt.inAddress); (err != nil) != tt.wantErr {
				t.Fatalf("AddInterface(%s, %s): did not get expected error, got: %v, wantErr? %v", tt.inInterface, tt.inAddress, err, tt.wantErr)
			}
		})
	}
}
