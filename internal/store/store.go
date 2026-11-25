package store

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/TechieEngineer/netspectra/internal/scanner"
	"io"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Store struct {
	DB        *sql.DB
	lock      string
	closeOnce sync.Once
	closeErr  error
}

// Close releases the database and its single-process guard.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.DB.Close()
		if s.closeErr == nil {
			s.closeErr = os.Remove(s.lock)
		}
	})
	return s.closeErr
}

type Scan struct {
	ID       string `json:"id"`
	CIDR     string `json:"cidr"`
	Status   string `json:"status"`
	Started  string `json:"started"`
	Finished string `json:"finished"`
	Done     int    `json:"done"`
	Total    int    `json:"total"`
}
type Key struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func Open(path string) (*Store, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, e
	}
	path = abs
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(path))
	if e != nil {
		return nil, e
	}
	path = filepath.Join(parent, filepath.Base(path))
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("database must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	lock := path + ".lock"
	if e = os.Mkdir(lock, 0700); e != nil {
		return nil, errors.New("database already in use or lock cannot be created; see SECURITY.md")
	}
	success := false
	defer func() {
		if !success {
			_ = os.Remove(lock)
		}
	}()
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	f.Close()
	if e = os.Chmod(path, 0600); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, lock: lock}
	var schema int
	if e = db.QueryRow("PRAGMA user_version").Scan(&schema); e != nil || schema > 1 {
		db.Close()
		return nil, errors.New("unsupported database schema")
	}
	_, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY,v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys(id TEXT PRIMARY KEY,name TEXT NOT NULL,hash TEXT UNIQUE NOT NULL,created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY,cidr TEXT NOT NULL,status TEXT NOT NULL,started TEXT NOT NULL,finished TEXT NOT NULL DEFAULT '',done INTEGER NOT NULL DEFAULT 0,total INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS observations(scan_id TEXT NOT NULL REFERENCES scans(id),ip TEXT NOT NULL,mac TEXT NOT NULL,vendor TEXT NOT NULL,ports TEXT NOT NULL,PRIMARY KEY(scan_id,ip));
CREATE TABLE IF NOT EXISTS oui(prefix TEXT PRIMARY KEY,vendor TEXT NOT NULL);
UPDATE scans SET status='interrupted',finished=datetime('now') WHERE status='running';
PRAGMA user_version=1;`)
	if e != nil {
		db.Close()
		return nil, e
	}
	success = true
	return s, nil
}
func (s *Store) Get(k string) (string, error) {
	var v string
	e := s.DB.QueryRow("SELECT v FROM settings WHERE k=?", k).Scan(&v)
	if errors.Is(e, sql.ErrNoRows) {
		return "", nil
	}
	return v, e
}
func (s *Store) Set(k, v string) error {
	_, e := s.DB.Exec("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", k, v)
	return e
}
func (s *Store) SetOnce(k, v string) (bool, error) {
	r, e := s.DB.Exec("INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)", k, v)
	if e != nil {
		return false, e
	}
	n, e := r.RowsAffected()
	return n == 1, e
}
func (s *Store) BeginScan(id, cidr string, total int) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("DELETE FROM observations WHERE scan_id IN (SELECT id FROM scans WHERE status!='running' ORDER BY started DESC,id DESC LIMIT -1 OFFSET 99)"); e != nil {
		return e
	}
	if _, e = tx.Exec("DELETE FROM scans WHERE id IN (SELECT id FROM scans WHERE status!='running' ORDER BY started DESC,id DESC LIMIT -1 OFFSET 99)"); e != nil {
		return e
	}
	if _, e = tx.Exec("INSERT INTO scans(id,cidr,status,started,total) VALUES(?,?,'running',?,?)", id, cidr, Now(), total); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) Record(id string, h scanner.Host) error {
	p, e := json.Marshal(h.Ports)
	if e != nil {
		return e
	}
	_, e = s.DB.Exec("INSERT INTO observations(scan_id,ip,mac,vendor,ports) VALUES(?,?,?,?,?)", id, h.IP, h.MAC, h.Vendor, string(p))
	return e
}
func (s *Store) Progress(id string, n int) error {
	_, e := s.DB.Exec("UPDATE scans SET done=? WHERE id=?", n, id)
	return e
}
func (s *Store) Finish(id, status string) error {
	_, e := s.DB.Exec("UPDATE scans SET status=?,finished=? WHERE id=?", status, Now(), id)
	return e
}
func (s *Store) Scans() ([]Scan, error) {
	r, e := s.DB.Query("SELECT id,cidr,status,started,finished,done,total FROM scans ORDER BY started DESC LIMIT 100")
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := []Scan{}
	for r.Next() {
		var v Scan
		if e = r.Scan(&v.ID, &v.CIDR, &v.Status, &v.Started, &v.Finished, &v.Done, &v.Total); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, r.Err()
}
func (s *Store) Hosts(id string) ([]scanner.Host, error) {
	q := `SELECT ip,mac,vendor,ports FROM observations WHERE scan_id=? ORDER BY ip`
	if id == "" {
		q = `SELECT ip,mac,vendor,ports FROM observations WHERE scan_id=(SELECT id FROM scans ORDER BY started DESC LIMIT 1) ORDER BY ip`
	}
	var r *sql.Rows
	var e error
	if id == "" {
		r, e = s.DB.Query(q)
	} else {
		r, e = s.DB.Query(q, id)
	}
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := []scanner.Host{}
	for r.Next() {
		var h scanner.Host
		var p string
		if e = r.Scan(&h.IP, &h.MAC, &h.Vendor, &p); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(p), &h.Ports); e != nil {
			return nil, e
		}
		out = append(out, h)
	}
	return out, r.Err()
}
func (s *Store) Vendor(mac string) string {
	p := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))
	if len(p) < 6 {
		return ""
	}
	var v string
	_ = s.DB.QueryRow("SELECT vendor FROM oui WHERE prefix=?", p[:6]).Scan(&v)
	return v
}
func (s *Store) ImportOUI(ctx context.Context, r io.Reader) error {
	c := csv.NewReader(r)
	head, e := c.Read()
	if e != nil {
		return e
	}
	a, v := -1, -1
	for i, x := range head {
		switch strings.TrimSpace(x) {
		case "Assignment":
			a = i
		case "Organization Name":
			v = i
		}
	}
	if a < 0 || v < 0 {
		return errors.New("expected IEEE MA-L CSV")
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	st, e := tx.Prepare("INSERT OR REPLACE INTO oui(prefix,vendor) VALUES(?,?)")
	if e != nil {
		return e
	}
	defer st.Close()
	for {
		row, e := c.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		p := strings.ToUpper(strings.TrimSpace(row[a]))
		if len(p) != 6 {
			continue
		}
		if _, e := hex.DecodeString(p); e != nil {
			continue
		}
		if _, e = st.Exec(p, row[v]); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) CreateKey(id, name, hash string) error {
	r, e := s.DB.Exec("INSERT INTO api_keys SELECT ?,?,?,? WHERE (SELECT count(*) FROM api_keys)<32", id, name, hash, Now())
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e == nil && n != 1 {
		return errors.New("API key limit reached")
	}
	return e
}
func (s *Store) Keys() ([]Key, error) {
	r, e := s.DB.Query("SELECT id,name,created FROM api_keys ORDER BY created DESC")
	if e != nil {
		return nil, e
	}
	defer r.Close()
	out := []Key{}
	for r.Next() {
		var k Key
		if e = r.Scan(&k.ID, &k.Name, &k.Created); e != nil {
			return nil, e
		}
		out = append(out, k)
	}
	return out, r.Err()
}
func (s *Store) RevokeKey(id string) error {
	_, e := s.DB.Exec("DELETE FROM api_keys WHERE id=?", id)
	return e
}
func (s *Store) KeyValid(hash string) bool {
	var n int
	return s.DB.QueryRow("SELECT 1 FROM api_keys WHERE hash=?", hash).Scan(&n) == nil
}
func (s *Store) Session(hash string, expires int64) error {
	_, e := s.DB.Exec("INSERT INTO sessions VALUES(?,?)", hash, expires)
	return e
}
func (s *Store) SessionValid(hash string) bool {
	var n int
	return s.DB.QueryRow("SELECT 1 FROM sessions WHERE hash=? AND expires>?", hash, time.Now().Unix()).Scan(&n) == nil
}
func (s *Store) RevokeSession(hash string) error {
	_, e := s.DB.Exec("DELETE FROM sessions WHERE hash=?", hash)
	return e
}
func (s *Store) CleanSessions() error {
	_, e := s.DB.Exec("DELETE FROM sessions WHERE expires<=?", time.Now().Unix())
	return e
}
