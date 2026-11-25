package scanner

import (
	"context"
	"net/netip"
	"testing"
)

func TestScope(t *testing.T) {
	for _, x := range []string{"8.8.8.0/24", "192.168.0.0/16", "::1/128", "bad", "100.64.0.1/32"} {
		if _, e := ValidateCIDR(x); e == nil {
			t.Errorf("accepted %s", x)
		}
	}
	for _, x := range []string{"192.168.1.0/24", "10.0.0.1/32", "127.0.0.1/32"} {
		if _, e := ValidateCIDR(x); e != nil {
			t.Fatal(e)
		}
	}
}
func TestTargets(t *testing.T) {
	for _, x := range []struct {
		p string
		n int
	}{{"192.168.1.0/24", 254}, {"10.0.0.0/31", 2}, {"127.0.0.1/32", 1}} {
		if n := len(Targets(netip.MustParsePrefix(x.p))); n != x.n {
			t.Errorf("%s: %d", x.p, n)
		}
	}
}
func TestCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := Scan(ctx, "127.0.0.1/32", nil)
	if e == nil {
		t.Fatal("expected cancellation")
	}
}
