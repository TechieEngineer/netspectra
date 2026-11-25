package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/TechieEngineer/netspectra/internal/auth"
	"github.com/TechieEngineer/netspectra/internal/scanner"
	"github.com/TechieEngineer/netspectra/internal/server"
	"github.com/TechieEngineer/netspectra/internal/store"
	"github.com/TechieEngineer/netspectra/web"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var version = "1.0.0-rc.1"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	host := flag.String("host", "127.0.0.1", "bind address (non-loopback requires TLS and existing admin)")
	port := flag.Int("port", 8080, "HTTP port")
	db := flag.String("db", "data/netscan.db", "SQLite path")
	cidr := flag.String("cidr", "", "headless private CIDR")
	asJSON := flag.Bool("json", false, "JSON output in headless mode")
	authorized := flag.Bool("authorized", false, "confirm permission for headless scan")
	cert := flag.String("tls-cert", "", "TLS certificate")
	key := flag.String("tls-key", "", "TLS key")
	oui := flag.String("oui-file", "", "optional IEEE MA-L CSV import")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *port < 1 || *port > 65535 {
		log.Fatal("invalid port")
	}
	if (*cert == "") != (*key == "") {
		log.Fatal("both TLS certificate and key are required")
	}
	secure := *cert != ""
	loop := *host == "localhost" || *host == "127.0.0.1" || *host == "::1"
	if *cidr == "" && !loop && (!secure || net.ParseIP(*host) == nil || net.ParseIP(*host).IsUnspecified()) {
		log.Fatal("remote binding requires a specific IP and TLS; wildcard binding is disabled")
	}
	if *cidr != "" {
		if !*authorized {
			log.Fatal("--authorized is required")
		}
		if _, e := scanner.ValidateCIDR(*cidr); e != nil {
			log.Fatal(e)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	s, e := store.Open(*db)
	if e != nil {
		log.Fatal(e)
	}
	defer s.Close()
	a, e := auth.New(s, secure)
	if e != nil {
		_ = s.Close()
		log.Fatal(e)
	}
	h, e := s.Get("admin_hash")
	if e != nil {
		_ = s.Close()
		log.Fatal(e)
	}
	if p := os.Getenv("ADMIN_PASSWORD"); p != "" && h == "" {
		if _, e = a.Setup(p); e != nil {
			_ = s.Close()
			log.Fatal(e)
		}
		h, e = s.Get("admin_hash")
		if e != nil {
			_ = s.Close()
			log.Fatal(e)
		}
	}
	if *oui != "" {
		f, e := os.Open(*oui)
		if e != nil {
			_ = s.Close()
			log.Fatal(e)
		}
		e = s.ImportOUI(ctx, f)
		f.Close()
		if e != nil {
			_ = s.Close()
			log.Fatal(e)
		}
	}
	if *cidr != "" {
		if e = cli(ctx, s, *cidr, *asJSON); e != nil {
			_ = s.Close()
			log.Fatal(e)
		}
		return
	}
	if !loop && h == "" {
		_ = s.Close()
		log.Fatal("configure ADMIN_PASSWORD on first remote startup")
	}
	v := server.New(ctx, s, a, *host, strconv.Itoa(*port), web.Handler())
	httpd := &http.Server{Addr: net.JoinHostPort(*host, strconv.Itoa(*port)), Handler: v.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	errs := make(chan error, 1)
	go func() {
		log.Printf("dashboard listening on %s (TLS=%t)", httpd.Addr, secure)
		if secure {
			errs <- httpd.ListenAndServeTLS(*cert, *key)
		} else {
			errs <- httpd.ListenAndServe()
		}
	}()
	var serveErr error
	select {
	case <-ctx.Done():
	case e := <-errs:
		if !errors.Is(e, http.ErrServerClosed) {
			log.Print(e)
			serveErr = e
		}
		cancel()
	}
	shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	_ = httpd.Shutdown(shutdown)
	v.Wait()
	if serveErr != nil {
		_ = s.Close()
		os.Exit(1)
	}
}
func cli(ctx context.Context, s *store.Store, cidr string, asJSON bool) error {
	p, e := scanner.ValidateCIDR(cidr)
	if e != nil {
		return e
	}
	id, e := auth.Random(16)
	if e != nil {
		return e
	}
	if e = s.BeginScan(id, p.String(), len(scanner.Targets(p))); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	var persist error
	hosts, e := scanner.Scan(ctx, p.String(), func(v scanner.Progress) {
		if persist != nil {
			return
		}
		if v.Host != nil {
			v.Host.Vendor = s.Vendor(v.Host.MAC)
			persist = s.Record(id, *v.Host)
		}
		if persist == nil {
			persist = s.Progress(id, v.Done)
		}
		if persist != nil {
			cancel()
		}
	})
	status := "completed"
	if e != nil {
		status = "interrupted"
	}
	if persist != nil {
		status = "failed"
	}
	if err := s.Finish(id, status); err != nil {
		return err
	}
	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"id": id, "status": status, "hosts": hosts}); err != nil {
			return err
		}
	} else {
		for _, h := range hosts {
			fmt.Printf("%s  %s  %v\n", h.IP, h.Vendor, h.Ports)
		}
		fmt.Printf("%s: %d hosts\n", status, len(hosts))
	}
	if persist != nil {
		return persist
	}
	return e
}
