package arp

import (
	"testing"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/magna/lwotgtelem"
)

func TestNeighUpdates(t *testing.T) {
	tests := []struct {
		desc              string
		inTarget          string
		inHintFn          func() lwotgtelem.HintMap
		timeFn            func() int64
		wantNotifications []*gpb.Notification
		wantErr           bool
	}{{}}
}
