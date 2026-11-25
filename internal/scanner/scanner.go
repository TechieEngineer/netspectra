// Package scanner performs bounded TCP discovery on private IPv4 networks.
package scanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const MaxWorkers = 16

var ports = []int{22, 53, 80, 443, 445, 631, 1883, 3000, 3389, 5432, 8000, 8080}
var services = map[int]string{22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB", 631: "IPP", 1883: "MQTT", 3000: "HTTP alternate", 3389: "RDP", 5432: "PostgreSQL", 8000: "HTTP alternate", 8080: "HTTP alternate"}

type Port struct {
	Number  int    `json:"number"`
	Service string `json:"service"`
}
type Host struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Vendor string `json:"vendor"`
	Ports  []Port `json:"ports"`
}
type Progress struct {
	Done  int   `json:"done"`
	Total int   `json:"total"`
	Host  *Host `json:"host,omitempty"`
}

var private = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("127.0.0.0/8")}

func ValidateCIDR(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil || !p.Addr().Is4() || p.Bits() < 24 {
		return netip.Prefix{}, errors.New("use a private IPv4 CIDR between /24 and /32")
	}
	p = p.Masked()
	for _, a := range private {
		if p.Bits() >= a.Bits() && a.Contains(p.Addr()) {
			return p, nil
		}
	}
	return netip.Prefix{}, errors.New("only RFC1918 private IPv4 and loopback networks are supported")
}
func LocalCIDRs() []string {
	out := []string{}
	seen := map[string]bool{}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			p, e := netip.ParsePrefix(a.String())
			if e != nil || !p.Addr().Is4() {
				continue
			}
			if p.Bits() < 24 {
				p = netip.PrefixFrom(p.Addr(), 24)
			}
			p, e = ValidateCIDR(p.String())
			if e == nil && !seen[p.String()] {
				seen[p.String()] = true
				out = append(out, p.String())
			}
		}
	}
	sort.Strings(out)
	return out
}
func Targets(p netip.Prefix) []netip.Addr {
	p = p.Masked()
	out := []netip.Addr{}
	for a := p.Addr(); a.IsValid() && p.Contains(a); a = a.Next() {
		out = append(out, a)
	}
	if p.Bits() <= 30 && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out
}

// Scan uses ordinary TCP connects, with a global launch interval and fixed worker ceiling.
// A refused TCP connection is positive evidence of reachability, not an open port.
func Scan(ctx context.Context, raw string, progress func(Progress)) ([]Host, error) {
	p, e := ValidateCIDR(raw)
	if e != nil {
		return nil, e
	}
	targets := Targets(p)
	jobs := make(chan netip.Addr)
	results := make(chan *Host, MaxWorkers)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	var wg sync.WaitGroup
	for i := 0; i < MaxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				h := Host{IP: a.String(), Ports: []Port{}}
				alive := false
				for _, port := range ports {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
					}
					d := net.Dialer{Timeout: 350 * time.Millisecond}
					c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(h.IP, strconv.Itoa(port)))
					if err == nil {
						alive = true
						c.Close()
						h.Ports = append(h.Ports, Port{port, services[port]})
					} else if errors.Is(err, syscall.ECONNREFUSED) {
						alive = true
					}
				}
				var result *Host
				if alive {
					h.MAC = arpMAC(h.IP)
					result = &h
				}
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, a := range targets {
			select {
			case jobs <- a:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	hosts := []Host{}
	done := 0
	for h := range results {
		done++
		if h != nil {
			hosts = append(hosts, *h)
		}
		if progress != nil {
			progress(Progress{done, len(targets), h})
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return netip.MustParseAddr(hosts[i].IP).Less(netip.MustParseAddr(hosts[j].IP)) })
	return hosts, ctx.Err()
}

// Linux neighbor cache only; no raw packets. Missing MACs are normal on other platforms.
func arpMAC(ip string) string {
	f, e := os.Open("/proc/net/arp")
	if e != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		v := strings.Fields(s.Text())
		if len(v) >= 4 && v[0] == ip && v[2] == "0x2" {
			m, e := net.ParseMAC(v[3])
			if e == nil && fmt.Sprint(m) != "00:00:00:00:00:00" {
				return m.String()
			}
		}
	}
	return ""
}
