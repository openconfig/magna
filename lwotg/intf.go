package lwotg

import (
	"net"

	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// intf describes an interface in the OTG configuration.
type intf struct {
	// OTGEthernetName specifies the name of the interface in the OTG configuration when referred to
	// as an Ethernet port.
	OTGEthernetName string
	// OTGPortName specifies the name of the interface in the overall OTG configuration.
	OTGPortName string
	// SystemName specifies the name of the interface on the system.
	SystemName string
	// IPv4 specifies the IPv4 addresses associated with the interface.
	IPv4 []*ipAddress
}

// ipAddress specifies an IP address that can be associated with an interface.
type ipAddress struct {
	// Address specifies the IPv4 or IPv6 address that is to be configured.
	Address net.IP
	// Mask specifies the CIDR mask of the address.
	Mask int
	// Configured specifies whether the address has been configured.
	Configured bool
	// Gateway indicates the remote IP address on the interface, which is mandatory
	// in the OTG specification.
	Gateway net.IP
}

// portsToSystem takes an input set of ports and devices from an OTG configuration and returns the
// information that is required to configure them on the underlying host. The OTG "ports" stanza contains
// a set of ports that have a name and a location. The location is the name of the interface on the
// underlying system. OTG devices have a set of ethernet ports that are associated with them, which
// use the names that are specified in the ports map.
//
// It returns a slice of intf structs that describe the system interfaces.
func portsToSystem(ports []*otg.Port, devices []*otg.Device) ([]*intf, error) {
	physIntf := map[string]string{}
	for _, p := range ports {
		if p.Location == nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid interface %s, does not specify a port location", p.Name)
		}
		physIntf[p.Name] = *p.Location
	}

	intfs := []*intf{}
	for _, d := range devices {
		for _, e := range d.Ethernets {
			if e.GetPortName() == "" {
				return nil, status.Errorf(codes.InvalidArgument, "invalid Ethernet port %v, does not specify a name", e)
			}
			sysInt, ok := physIntf[*e.PortName]
			if !ok {
				return nil, status.Errorf(codes.InvalidArgument, "invalid port name for Ethernet %s, does not map to a physical interface", *e.PortName)
			}

			i := &intf{
				OTGEthernetName: e.Name,
				OTGPortName:     *e.PortName,
				SystemName:      sysInt,
				IPv4:            []*ipAddress{},
			}

			for _, a := range e.Ipv4Addresses {
				if a.GetPrefix() == 0 {
					return nil, status.Errorf(codes.InvalidArgument, "unsupported zero prefix length for address %s", a.Address)
				}

				i.IPv4 = append(i.IPv4, &ipAddress{
					Address: net.ParseIP(a.Address),
					Mask:    int(a.GetPrefix()),
					Gateway: net.ParseIP(a.Gateway),
				})
			}

			intfs = append(intfs, i)
		}
	}

	return intfs, nil
}
