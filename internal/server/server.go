package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TechieEngineer/netspectra/internal/auth"
	"github.com/TechieEngineer/netspectra/internal/scanner"
	"github.com/TechieEngineer/netspectra/internal/store"
	"github.com/gorilla/websocket"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Server struct {
	S           *store.Store
	A           *auth.Auth
	Ctx         context.Context
	AllowedHost string
	Port        string
	UI          http.Handler
	mu          sync.Mutex
	running     bool
	wg          sync.WaitGroup
	gate        chan struct{}
	wsGate      chan struct{}
	lastLogin   time.Time
	loginMu     sync.Mutex
	hooks       map[string]string
}

func New(ctx context.Context, s *store.Store, a *auth.Auth, host, port string, ui http.Handler) *Server {
	v := &Server{S: s, A: a, Ctx: ctx, AllowedHost: host, Port: port, UI: ui, gate: make(chan struct{}, 1), wsGate: make(chan struct{}, 8), hooks: map[string]string{}}
	for _, k := range []string{"discord", "slack", "generic"} {
		raw := os.Getenv("WEBHOOK_" + strings.ToUpper(k) + "_URL")
		u, e := url.Parse(raw)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			continue
		}
		if k == "discord" && u.Hostname() != "discord.com" {
			continue
		}
		if k == "slack" && u.Hostname() != "hooks.slack.com" {
			continue
		}
		v.hooks[k] = raw
	}
	return v
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if e := json.NewEncoder(w).Encode(v); e != nil {
		log.Print("response write failed")
	}
}
func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}
func body(w http.ResponseWriter, r *http.Request, v any) bool {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		fail(w, 415, "application/json required")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		fail(w, 400, "invalid JSON body")
		return false
	}
	return true
}
func (s *Server) sameOrigin(r *http.Request) bool {
	scheme := "http"
	if s.A.Secure {
		scheme = "https"
	}
	return r.Header.Get("Origin") == scheme+"://"+r.Host
}
func (s *Server) validHost(r *http.Request) bool {
	h, p, e := net.SplitHostPort(r.Host)
	if e != nil {
		h = strings.TrimPrefix(strings.TrimSuffix(r.Host, "]"), "[")
		p = ""
	}
	if p != s.Port && !(p == "" && ((s.A.Secure && s.Port == "443") || (!s.A.Secure && s.Port == "80"))) {
		return false
	}
	if s.AllowedHost == "127.0.0.1" || s.AllowedHost == "::1" || s.AllowedHost == "localhost" {
		return h == "127.0.0.1" || h == "localhost" || h == "[::1]" || h == "::1"
	}
	return strings.EqualFold(h, s.AllowedHost)
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/v1/status", s.status)
	m.HandleFunc("POST /api/v1/setup", s.login(true))
	m.HandleFunc("POST /api/v1/login", s.login(false))
	m.HandleFunc("POST /api/v1/logout", s.session(s.logout))
	m.HandleFunc("GET /api/v1/cidrs", s.protected(s.cidrs))
	m.HandleFunc("POST /api/v1/scan", s.protected(s.start))
	m.HandleFunc("GET /api/v1/scans", s.protected(s.scans))
	m.HandleFunc("GET /api/v1/hosts", s.protected(s.hosts))
	m.HandleFunc("GET /api/v1/keys", s.session(s.keys))
	m.HandleFunc("POST /api/v1/keys", s.session(s.createKey))
	m.HandleFunc("DELETE /api/v1/keys/{id}", s.session(s.revokeKey))
	m.HandleFunc("GET /api/v1/webhooks", s.session(s.getHooks))
	m.HandleFunc("PUT /api/v1/webhooks", s.session(s.setHook))
	m.HandleFunc("GET /api/v1/ws", s.session(s.ws))
	m.HandleFunc("GET /metrics", s.protected(s.metrics))
	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "not found") })
	m.Handle("/", s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		if !s.validHost(r) {
			fail(w, 403, "host not allowed")
			return
		}
		wsScheme := "ws://"
		if s.A.Secure {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			wsScheme = "wss://"
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' "+wsScheme+r.Host+"; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Origin") != "" && !s.sameOrigin(r) {
				fail(w, 403, "origin not allowed")
				return
			}
			if r.Header.Get("Authorization") == "" && !s.sameOrigin(r) {
				fail(w, 403, "same-origin browser request required")
				return
			}
		}
		m.ServeHTTP(w, r)
	})
}
func (s *Server) protected(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.A.Allowed(r) {
			fail(w, 401, "authentication required")
			return
		}
		h(w, r)
	}
}
func (s *Server) session(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.A.SessionOK(r) {
			fail(w, 401, "admin session required")
			return
		}
		if r.Method != "GET" && !s.sameOrigin(r) {
			fail(w, 403, "origin not allowed")
			return
		}
		h(w, r)
	}
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	h, e := s.S.Get("admin_hash")
	if e != nil {
		fail(w, 500, "storage unavailable")
		return
	}
	reply(w, 200, map[string]bool{"setupRequired": h == "", "authenticated": s.A.SessionOK(r)})
}
func (s *Server) login(setup bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.sameOrigin(r) {
			fail(w, 403, "origin not allowed")
			return
		}
		var v struct {
			Password string `json:"password"`
		}
		if !body(w, r, &v) {
			return
		}
		select {
		case s.gate <- struct{}{}:
			defer func() { <-s.gate }()
		default:
			fail(w, 429, "try again later")
			return
		}
		s.loginMu.Lock()
		if time.Since(s.lastLogin) < time.Second {
			s.loginMu.Unlock()
			fail(w, 429, "try again later")
			return
		}
		s.lastLogin = time.Now()
		s.loginMu.Unlock()
		if setup {
			h, e := s.S.Get("admin_hash")
			if e != nil {
				fail(w, 500, "storage unavailable")
				return
			}
			if h != "" {
				fail(w, 409, "already configured")
				return
			}
			if len(v.Password) < 12 || len(v.Password) > 72 {
				fail(w, 400, "password must contain 12–72 bytes")
				return
			}
			ok, e := s.A.Setup(v.Password)
			if e != nil {
				fail(w, 500, "setup failed")
				return
			}
			if !ok {
				fail(w, 409, "already configured")
				return
			}
		} else if !s.A.Check(v.Password) {
			fail(w, 401, "invalid credentials")
			return
		}
		if e := s.A.Issue(w); e != nil {
			fail(w, 500, "session creation failed")
			return
		}
		_ = s.S.CleanSessions()
		reply(w, 200, map[string]bool{"ok": true})
	}
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if e := s.A.Logout(w, r); e != nil {
		fail(w, 500, "logout failed")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) cidrs(w http.ResponseWriter, r *http.Request) { reply(w, 200, scanner.LocalCIDRs()) }
func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	var v struct {
		CIDR       string `json:"cidr"`
		Authorized bool   `json:"authorized"`
	}
	if !body(w, r, &v) {
		return
	}
	if !v.Authorized {
		fail(w, 400, "authorization confirmation required")
		return
	}
	p, e := scanner.ValidateCIDR(v.CIDR)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.Ctx.Err() != nil {
		fail(w, 409, "scanner busy or shutting down")
		return
	}
	id, e := auth.Random(16)
	if e != nil {
		fail(w, 500, "scan creation failed")
		return
	}
	if e = s.S.BeginScan(id, p.String(), len(scanner.Targets(p))); e != nil {
		fail(w, 500, "scan creation failed")
		return
	}
	s.running = true
	s.wg.Add(1)
	go s.run(id, p.String())
	reply(w, 202, map[string]string{"id": id, "status": "running"})
}
func (s *Server) run(id, cidr string) {
	defer s.wg.Done()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(s.Ctx, 5*time.Minute)
	defer cancel()
	var storageErr error
	count := 0
	_, e := scanner.Scan(ctx, cidr, func(p scanner.Progress) {
		if storageErr != nil {
			return
		}
		if p.Host != nil {
			p.Host.Vendor = s.S.Vendor(p.Host.MAC)
			storageErr = s.S.Record(id, *p.Host)
			count++
		}
		if storageErr == nil {
			storageErr = s.S.Progress(id, p.Done)
		}
		if storageErr != nil {
			cancel()
		}
	})
	state := "completed"
	if e != nil {
		state = "interrupted"
	}
	if storageErr != nil {
		state = "failed"
		log.Print("scan storage error")
	}
	if err := s.S.Finish(id, state); err != nil {
		log.Print("scan finalization failed")
		return
	}
	if s.Ctx.Err() == nil {
		s.notify(id, cidr, state, count)
	}
}
func (s *Server) Wait() { s.mu.Lock(); s.mu.Unlock(); s.wg.Wait() }
func (s *Server) scans(w http.ResponseWriter, r *http.Request) {
	v, e := s.S.Scans()
	if e != nil {
		fail(w, 500, "storage unavailable")
		return
	}
	reply(w, 200, v)
}
func (s *Server) hosts(w http.ResponseWriter, r *http.Request) {
	v, e := s.S.Hosts(r.URL.Query().Get("scan_id"))
	if e != nil {
		fail(w, 500, "storage unavailable")
		return
	}
	reply(w, 200, v)
}
func (s *Server) keys(w http.ResponseWriter, r *http.Request) {
	v, e := s.S.Keys()
	if e != nil {
		fail(w, 500, "storage unavailable")
		return
	}
	reply(w, 200, v)
}
func (s *Server) createKey(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Name string `json:"name"`
	}
	if !body(w, r, &v) {
		return
	}
	v.Name = strings.TrimSpace(v.Name)
	if len(v.Name) == 0 || len(v.Name) > 80 {
		fail(w, 400, "name must contain 1–80 bytes")
		return
	}
	id, e := auth.Random(16)
	if e != nil {
		fail(w, 500, "key creation failed")
		return
	}
	k, e := auth.Random(32)
	if e != nil {
		fail(w, 500, "key creation failed")
		return
	}
	if e = s.S.CreateKey(id, v.Name, auth.Hash(k)); e != nil {
		fail(w, 500, "key creation failed")
		return
	}
	reply(w, 201, map[string]string{"id": id, "key": k})
}
func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) {
	if e := s.S.RevokeKey(r.PathValue("id")); e != nil {
		fail(w, 500, "key revocation failed")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}

type hook struct {
	Provider   string `json:"provider"`
	Configured bool   `json:"configured"`
	Enabled    bool   `json:"enabled"`
}

func (s *Server) getHooks(w http.ResponseWriter, r *http.Request) {
	out := []hook{}
	for _, k := range []string{"discord", "slack", "generic"} {
		v, e := s.S.Get("hook_" + k)
		if e != nil {
			fail(w, 500, "storage unavailable")
			return
		}
		out = append(out, hook{k, s.hooks[k] != "", v == "true"})
	}
	reply(w, 200, out)
}
func (s *Server) setHook(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Provider string `json:"provider"`
		Enabled  bool   `json:"enabled"`
	}
	if !body(w, r, &v) {
		return
	}
	if v.Provider != "discord" && v.Provider != "slack" && v.Provider != "generic" {
		fail(w, 400, "unknown provider")
		return
	}
	if v.Enabled && s.hooks[v.Provider] == "" {
		fail(w, 400, "configure the URL in the server environment first")
		return
	}
	if e := s.S.Set("hook_"+v.Provider, fmt.Sprint(v.Enabled)); e != nil {
		fail(w, 500, "storage unavailable")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) notify(id, cidr, state string, n int) {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	for k, u := range s.hooks {
		v, e := s.S.Get("hook_" + k)
		if e != nil || v != "true" {
			continue
		}
		msg := fmt.Sprintf("Network scan %s: %s (%d observed hosts)", id, state, n)
		var data any = map[string]any{"id": id, "status": state, "hosts": n}
		if k == "discord" {
			data = map[string]string{"content": msg}
		}
		if k == "slack" {
			data = map[string]string{"text": msg}
		}
		b, _ := json.Marshal(data)
		req, e := http.NewRequestWithContext(s.Ctx, "POST", u, bytes.NewReader(b))
		if e != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(req)
		if e != nil {
			log.Printf("%s webhook failed", k)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			log.Printf("%s webhook returned %d", k, resp.StatusCode)
		}
	}
}
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	var scans, hosts, running int
	e := s.S.DB.QueryRow("SELECT count(*),coalesce(sum(CASE WHEN status='running' THEN 1 ELSE 0 END),0) FROM scans").Scan(&scans, &running)
	if e == nil {
		e = s.S.DB.QueryRow("SELECT count(*) FROM observations").Scan(&hosts)
	}
	if e != nil {
		fail(w, 500, "storage unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE netscan_retained_scans gauge\nnetscan_retained_scans %d\n# TYPE netscan_retained_observations gauge\nnetscan_retained_observations %d\n# TYPE netscan_running gauge\nnetscan_running %d\n", scans, hosts, running)
}
func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		fail(w, 403, "origin not allowed")
		return
	}
	select {
	case s.wsGate <- struct{}{}:
		defer func() { <-s.wsGate }()
	default:
		fail(w, 429, "too many connections")
		return
	}
	up := websocket.Upgrader{CheckOrigin: s.sameOrigin, HandshakeTimeout: 5 * time.Second}
	c, e := up.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	defer c.Close()
	c.SetReadLimit(1024)
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.SetPongHandler(func(string) error { return c.SetReadDeadline(time.Now().Add(60 * time.Second)) })
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for {
			if _, _, e := c.ReadMessage(); e != nil {
				return
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-s.Ctx.Done():
			return
		case <-closed:
			return
		case <-ping.C:
			if c.WriteControl(websocket.PingMessage, nil, time.Now().Add(3*time.Second)) != nil {
				return
			}
		case <-tick.C:
			if !s.A.SessionOK(r) {
				return
			}
			v, e := s.S.Scans()
			if e != nil {
				return
			}
			if len(v) > 0 {
				_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if c.WriteJSON(v[0]) != nil {
					return
				}
			}
		}
	}
}
