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
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func mustParseMAC(t *testing.T, mac string) net.HardwareAddr {
	m, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("invalid MAC address %s supplied", mac)
	}
	return m
}

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

type awaitARPAccessor struct {
	unimplementedAccessor
}

func (a *awaitARPAccessor) ARPList() ([]*ARPEntry, error) {
	m, err := net.ParseMAC("01:01:01:01:01:01")
	if err != nil {
		return nil, fmt.Errorf("cannot parse MAC, %v", err)
	}
	return []*ARPEntry{{
		IP:        net.ParseIP("192.0.2.1"),
		Interface: &Interface{Name: "eth0"},
		MAC:       m,
	}}, nil
}

func (a *awaitARPAccessor) ARPSubscribe(upch chan ARPUpdate, done chan struct{}) error {
	if upch == nil || done == nil {
		return fmt.Errorf("unspecified channels")
	}

	macs := []net.HardwareAddr{}
	for _, m := range []string{"02:02:02:02:02:02", "03:03:03:03:03:03"} {
		mac, err := net.ParseMAC(m)
		if err != nil {
			return fmt.Errorf("cannot parse MAC %s, test error", m)
		}
		macs = append(macs, mac)
	}

	updates := []ARPUpdate{{
		Type: ARPDelete,
		Neigh: ARPEntry{
			IP:        net.ParseIP("192.0.2.2"),
			Interface: &Interface{Name: "eth0"},
			MAC:       macs[0],
		},
	}, {
		Type: ARPAdd,
		Neigh: ARPEntry{
			IP:        net.ParseIP("192.0.2.3"),
			Interface: &Interface{Name: "eth1"},
			MAC:       macs[1],
		},
	}}

	for _, u := range updates {
		time.Sleep(100 * time.Millisecond)
		upch <- u
	}

	go func() {
		<-done
	}()
	return nil
}

func TestAwaitARP(t *testing.T) {
	oldAccessor := accessor
	defer func() {
		accessor = oldAccessor
	}()
	accessor = &awaitARPAccessor{}

	tests := []struct {
		desc      string
		inAddr    net.IP
		inTimeout time.Duration
		wantMAC   net.HardwareAddr
		wantErr   bool
	}{{
		desc:    "MAC resolved by list",
		inAddr:  net.ParseIP("192.0.2.1"),
		wantMAC: mustParseMAC(t, "01:01:01:01:01:01"),
	}, {
		desc:    "awaited MAC",
		inAddr:  net.ParseIP("192.0.2.3"),
		wantMAC: mustParseMAC(t, "03:03:03:03:03:03"),
	}, {
		desc:    "cannot be resolved",
		inAddr:  net.ParseIP("192.0.2.254"),
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			got, err := AwaitARP(ctx, tt.inAddr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error status, got: %v, wantErr? %v", err, tt.wantErr)
			}

			if !cmp.Equal(got, tt.wantMAC) {
				t.Fatalf("did not get expected MAC, got: %s, want: %s", got, tt.wantMAC)
			}
		})
	}
}
