package lwotg

import (
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"google.golang.org/protobuf/proto"
)

func TestPortsToSystem(t *testing.T) {
	tests := []struct {
		desc      string
		inPorts   []*otg.Port
		inDevices []*otg.Device
		wantIntf  []*otgIntf
		wantErr   bool
	}{{
		desc: "interface with no location",
		inPorts: []*otg.Port{{
			Name: "port1",
		}},
		wantErr: true,
	}, {
		desc: "ethernet port with no name",
		inPorts: []*otg.Port{{
			Name:     "port0",
			Location: proto.String("eth0"),
		}},
		inDevices: []*otg.Device{{
			Ethernets: []*otg.DeviceEthernet{{}},
		}},
		wantErr: true,
	}, {
		desc: "ethernet port with invalid location",
		inPorts: []*otg.Port{{
			Name:     "port0",
			Location: proto.String("eth0"),
		}},
		inDevices: []*otg.Device{{
			Ethernets: []*otg.DeviceEthernet{{
				Name:     "port0ETH",
				PortName: proto.String("port42"),
			}},
		}},
		wantErr: true,
	}, {
		desc: "ethernet port with no addresses",
		inPorts: []*otg.Port{{
			Name:     "port0",
			Location: proto.String("eth0"),
		}},
		inDevices: []*otg.Device{{
			Ethernets: []*otg.DeviceEthernet{{
				Name:     "port0ETH",
				PortName: proto.String("port0"),
			}},
		}},
		wantIntf: []*otgIntf{{
			OTGEthernetName: "port0ETH",
			OTGPortName:     "port0",
			SystemName:      "eth0",
		}},
	}, {
		desc: "ethernet port with IPv4 addresses",
		inPorts: []*otg.Port{{
			Name:     "port0",
			Location: proto.String("eth0"),
		}},
		inDevices: []*otg.Device{{
			Ethernets: []*otg.DeviceEthernet{{
				Name:     "port0ETH",
				PortName: proto.String("port0"),
				Ipv4Addresses: []*otg.DeviceIpv4{{
					Address: "192.0.2.1",
					Prefix:  proto.Int32(24),
					Gateway: "192.0.2.254",
				}},
			}},
		}},
		wantIntf: []*otgIntf{{
			OTGEthernetName: "port0ETH",
			OTGPortName:     "port0",
			SystemName:      "eth0",
			IPv4: []*ipAddress{{
				Address: net.ParseIP("192.0.2.1"),
				Mask:    24,
				Gateway: net.ParseIP("192.0.2.254"),
			}},
		}},
	}, {
		desc: "multiple addresses and interfaces",
		inPorts: []*otg.Port{{
			Name:     "port0",
			Location: proto.String("eth0"),
		}, {
			Name:     "port1",
			Location: proto.String("eth1"),
		}},
		inDevices: []*otg.Device{{
			Ethernets: []*otg.DeviceEthernet{{
				Name:     "port0ETH",
				PortName: proto.String("port0"),
				Ipv4Addresses: []*otg.DeviceIpv4{{
					Address: "192.0.2.1",
					Prefix:  proto.Int32(24),
					Gateway: "192.0.2.254",
				}, {
					Address: "10.0.0.1",
					Prefix:  proto.Int32(24),
					Gateway: "10.0.0.254",
				}},
			}, {
				Name:     "port1ETH",
				PortName: proto.String("port1"),
				Ipv4Addresses: []*otg.DeviceIpv4{{
					Address: "10.0.1.1",
					Prefix:  proto.Int32(24),
					Gateway: "10.0.1.254",
				}},
			}},
		}},
		wantIntf: []*otgIntf{{
			OTGEthernetName: "port0ETH",
			OTGPortName:     "port0",
			SystemName:      "eth0",
			IPv4: []*ipAddress{{
				Address: net.ParseIP("192.0.2.1"),
				Mask:    24,
				Gateway: net.ParseIP("192.0.2.254"),
			}, {
				Address: net.ParseIP("10.0.0.1"),
				Mask:    24,
				Gateway: net.ParseIP("10.0.0.254"),
			}},
		}, {
			OTGEthernetName: "port1ETH",
			OTGPortName:     "port1",
			SystemName:      "eth1",
			IPv4: []*ipAddress{{
				Address: net.ParseIP("10.0.1.1"),
				Mask:    24,
				Gateway: net.ParseIP("10.0.1.254"),
			}},
		}},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got, err := portsToSystem(tt.inPorts, tt.inDevices)
			if (err != nil) != tt.wantErr {
				t.Fatalf("did not get expected error status, got: %v, wantErr? %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(got, tt.wantIntf, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("did not get expected interfaces, diff(-got,+want):\n%s", diff)
			}
		})
	}
}
