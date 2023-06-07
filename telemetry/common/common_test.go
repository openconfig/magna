package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestAddTarget(t *testing.T) {
	tests := []struct {
		desc     string
		inNoti   *gpb.Notification
		inTarget string
		want     *gpb.Notification
	}{{
		desc:     "path with no prefix",
		inNoti:   &gpb.Notification{},
		inTarget: "dut",
		want: &gpb.Notification{
			Prefix: &gpb.Path{
				Origin: "openconfig",
				Target: "dut",
			},
		},
	}, {
		desc: "path with prefix with origin",
		inNoti: &gpb.Notification{
			Prefix: &gpb.Path{
				Origin: "foobar",
			},
		},
		inTarget: "dut",
		want: &gpb.Notification{
			Prefix: &gpb.Path{
				Origin: "foobar",
				Target: "dut",
			},
		},
	}, {
		desc: "path with empty origin - rewritten",
		inNoti: &gpb.Notification{
			Prefix: &gpb.Path{
				Origin: "",
			},
		},
		inTarget: "dut",
		want: &gpb.Notification{
			Prefix: &gpb.Path{
				Origin: "openconfig",
				Target: "dut",
			},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := AddTarget(tt.inNoti, tt.inTarget)
			if diff := cmp.Diff(got, tt.want, protocmp.Transform()); diff != "" {
				t.Fatalf("did not get expected notification, diff(-got,+want):\n%s", diff)
			}
		})
	}
}
