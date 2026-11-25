package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/TechieEngineer/netspectra/internal/store"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
)

const Cookie = "netscan_session"

type Auth struct {
	S      *store.Store
	aead   cipher.AEAD
	Secure bool
}

func Random(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func Hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func New(s *store.Store, secure bool) (*Auth, error) {
	k, e := s.Get("session_key")
	if e != nil {
		return nil, e
	}
	if k == "" {
		k, e = Random(32)
		if e != nil {
			return nil, e
		}
		if _, e = s.SetOnce("session_key", k); e != nil {
			return nil, e
		}
		k, e = s.Get("session_key")
		if e != nil {
			return nil, e
		}
	}
	b, e := base64.RawURLEncoding.DecodeString(k)
	if e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(b)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(block)
	return &Auth{s, a, secure}, e
}
func (a *Auth) Setup(password string) (bool, error) {
	if len(password) < 12 || len(password) > 72 {
		return false, errors.New("password must contain 12–72 bytes")
	}
	h, e := bcrypt.GenerateFromPassword([]byte(password), 12)
	if e != nil {
		return false, e
	}
	return a.S.SetOnce("admin_hash", string(h))
}
func (a *Auth) Check(password string) bool {
	if len(password) > 72 {
		return false
	}
	h, e := a.S.Get("admin_hash")
	return e == nil && h != "" && bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) == nil
}
func (a *Auth) Issue(w http.ResponseWriter) error {
	token, e := Random(32)
	if e != nil {
		return e
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	v := a.aead.Seal(nonce, nonce, []byte(token), []byte(Cookie))
	exp := time.Now().Add(8 * time.Hour)
	if e = a.S.Session(Hash(token), exp.Unix()); e != nil {
		return e
	}
	http.SetCookie(w, &http.Cookie{Name: Cookie, Value: base64.RawURLEncoding.EncodeToString(v), Path: "/", HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode, Expires: exp, MaxAge: 28800})
	return nil
}
func (a *Auth) SessionHash(r *http.Request) string {
	c, e := r.Cookie(Cookie)
	if e != nil {
		return ""
	}
	v, e := base64.RawURLEncoding.DecodeString(c.Value)
	n := a.aead.NonceSize()
	if e != nil || len(v) < n {
		return ""
	}
	p, e := a.aead.Open(nil, v[:n], v[n:], []byte(Cookie))
	if e != nil {
		return ""
	}
	return Hash(string(p))
}
func (a *Auth) SessionOK(r *http.Request) bool {
	h := a.SessionHash(r)
	return h != "" && a.S.SessionValid(h)
}
func (a *Auth) Allowed(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); h != "" {
		p, ok := strings.CutPrefix(h, "Bearer ")
		return ok && len(p) == 43 && a.S.KeyValid(Hash(p))
	}
	return a.SessionOK(r)
}
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) error {
	if h := a.SessionHash(r); h != "" {
		if e := a.S.RevokeSession(h); e != nil {
			return e
		}
	}
	http.SetCookie(w, &http.Cookie{Name: Cookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteStrictMode})
	return nil
}
