package server

import (
	"context"
	"github.com/TechieEngineer/netspectra/internal/auth"
	"github.com/TechieEngineer/netspectra/internal/store"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityLifecycle(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err := auth.New(s, false)
	if err != nil {
		t.Fatal(err)
	}
	h := New(context.Background(), s, a, "127.0.0.1", "8080", http.NotFoundHandler()).Handler()
	request := func(method, path, body, origin string, cookie *http.Cookie, bearer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	const origin = "http://127.0.0.1:8080"
	badHost := httptest.NewRequest("GET", "http://untrusted.invalid:8080/api/v1/status", nil)
	badResponse := httptest.NewRecorder()
	h.ServeHTTP(badResponse, badHost)
	if badResponse.Code != 403 {
		t.Fatal("unexpected Host accepted")
	}
	if w := request("GET", "/api/v1/hosts", "", "", nil, ""); w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if w := request("POST", "/api/v1/setup", `{"password":"temporary-test-only"}`, "https://example.org", nil, ""); w.Code != 403 {
		t.Fatalf("origin: %d", w.Code)
	}
	w := request("POST", "/api/v1/setup", `{"password":"temporary-test-only"}`, origin, nil, "")
	if w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	c := w.Result().Cookies()[0]
	if w = request("POST", "/api/v1/scan", `{"cidr":"127.0.0.1/32","authorized":false}`, origin, c, ""); w.Code != 400 {
		t.Fatalf("permission gate: %d", w.Code)
	}
	if w = request("POST", "/api/v1/scan", `{"cidr":"127.0.0.1/32","authorized":true}`, "https://untrusted.invalid", c, ""); w.Code != 403 {
		t.Fatalf("cross origin: %d", w.Code)
	}
	tampered := *c
	tampered.Value = "invalid"
	if w = request("GET", "/api/v1/hosts", "", "", &tampered, ""); w.Code != 401 {
		t.Fatalf("tampered cookie: %d", w.Code)
	}
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatal("cookie flags")
	}
	if w = request("GET", "/api/v1/hosts", "", "", c, ""); w.Code != 200 {
		t.Fatalf("session: %d", w.Code)
	}
	if w = request("POST", "/api/v1/scan", `{"cidr":"8.8.8.0/24","authorized":true}`, origin, c, ""); w.Code != 400 {
		t.Fatalf("public scope: %d", w.Code)
	}
	token, err := auth.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateKey("test", "test", auth.Hash(token)); err != nil {
		t.Fatal(err)
	}
	if w = request("GET", "/api/v1/hosts", "", "", nil, token); w.Code != 200 {
		t.Fatalf("bearer: %d", w.Code)
	}
	if w = request("GET", "/api/v1/keys", "", "", nil, token); w.Code != 401 {
		t.Fatalf("admin scope: %d", w.Code)
	}
	if w = request("DELETE", "/api/v1/keys/test", "", origin, c, ""); w.Code != 200 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if w = request("GET", "/api/v1/hosts", "", "", nil, token); w.Code != 401 {
		t.Fatalf("revoked: %d", w.Code)
	}
	if w = request("POST", "/api/v1/logout", "", origin, c, ""); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w = request("GET", "/api/v1/hosts", "", "", c, ""); w.Code != 401 {
		t.Fatalf("revoked session: %d", w.Code)
	}
}
