package common

import (
	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

const (
	// defaultOrigin encodes the origin that should be used by
	// default for any telemetry update.
	defaultOrigin = "openconfig"
)

// AddTarget adds the specified target name and an origin to the input gNMI
// Notification.
func AddTarget(n *gpb.Notification, target string) *gpb.Notification {
	if n.Prefix == nil {
		n.Prefix = &gpb.Path{}
	}
	n.Prefix.Target = target
	n.Prefix.Origin = defaultOrigin
	return n
}
