package store

import (
	"context"
	"fmt"
	"github.com/TechieEngineer/netspectra/internal/scanner"
	"path/filepath"
	"strings"
	"testing"
)

func TestInventory(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "test.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.ImportOUI(context.Background(), strings.NewReader("Registry,Assignment,Organization Name\nMA-L,001122,Test Vendor\n")); e != nil {
		t.Fatal(e)
	}
	if v := s.Vendor("00:11:22:00:00:00"); v != "Test Vendor" {
		t.Fatalf("vendor: %s", v)
	}
	if e = s.BeginScan("test", "127.0.0.1/32", 1); e != nil {
		t.Fatal(e)
	}
	if e = s.Record("test", scanner.Host{IP: "127.0.0.1", Ports: []scanner.Port{{Number: 8080, Service: "HTTP alternate"}}}); e != nil {
		t.Fatal(e)
	}
	if e = s.Progress("test", 1); e != nil {
		t.Fatal(e)
	}
	if e = s.Finish("test", "completed"); e != nil {
		t.Fatal(e)
	}
	h, e := s.Hosts("test")
	if e != nil || len(h) != 1 || len(h[0].Ports) != 1 {
		t.Fatalf("hosts: %v %v", h, e)
	}
	v, e := s.Scans()
	if e != nil || len(v) != 1 || v[0].Status != "completed" {
		t.Fatalf("scans: %v %v", v, e)
	}
}

func TestExclusiveOpenAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if another, err := Open(path); err == nil {
		another.Close()
		s.Close()
		t.Fatal("second open accepted")
	}
	if err := s.BeginScan("interrupted", "127.0.0.1/32", 1); err != nil {
		s.Close()
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	scans, err := s.Scans()
	if err != nil || len(scans) != 1 || scans[0].Status != "interrupted" {
		t.Fatalf("recovery: %v %v", scans, err)
	}
}

func TestRetention(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 102; i++ {
		id := fmt.Sprintf("scan-%03d", i)
		if err = s.BeginScan(id, "127.0.0.1/32", 1); err != nil {
			t.Fatal(err)
		}
		if err = s.Record(id, scanner.Host{IP: "127.0.0.1", Ports: []scanner.Port{}}); err != nil {
			t.Fatal(err)
		}
		if err = s.Finish(id, "completed"); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"scans", "observations"} {
		var n int
		if err = s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 100 {
			t.Fatalf("%s: %d %v", table, n, err)
		}
	}
}
