package wgctl

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRouteList(t *testing.T) {
	out := "10.42.1.0/24 proto 211 scope link metric 1000 \n10.0.5.20 proto 211 scope link metric 1000\nfd20::/64 proto 211 metric 1000 pref medium\n\n"
	got := parseRouteList(out)
	want := []string{"10.42.1.0/24", "10.0.5.20/32", "fd20::/64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseRouteList = %v; want %v", got, want)
	}
}

func TestSyncLinuxDiff(t *testing.T) {
	var calls []string
	origRun, origOut := runRoute, output
	runRoute = func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}
	output = func(name string, args ...string) (string, error) {
		if args[0] == "-4" {
			return "10.42.1.0/24 proto 211 scope link metric 1000\n10.99.0.0/16 proto 211 scope link metric 1000\n", nil
		}
		return "", nil
	}
	t.Cleanup(func() { runRoute, output = origRun, origOut })
	if err := syncLinux("wg0", canonList([]string{"10.42.1.0/24", "10.42.2.5/24"})); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip -4 route replace 10.42.2.0/24 dev wg0 proto 211 metric 1000",
		"ip -4 route del 10.99.0.0/16 dev wg0 proto 211 metric 1000",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v; want %v", calls, want)
	}
}
