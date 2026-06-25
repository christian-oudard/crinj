package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// Persistent OAuth token vault. Every captured login is one row: the real
// tokens plus the unique placeholders crinj handed the client. Rows are keyed
// by the issued (placeholder) access token, so a single issuer endpoint can
// hold many concurrent logins (multiple accounts, clients, or scopes). The
// vault survives a restart: the client keeps using its placeholders and crinj
// still maps them to the real tokens, with no re-login.
//
// The store reuses the pure-Go modernc.org/sqlite driver already registered by
// inject.go, so it adds no cgo and no new dependency.

const vaultSchema = `
CREATE TABLE IF NOT EXISTS token (
	issued_access  TEXT PRIMARY KEY,
	issued_refresh TEXT NOT NULL,
	real_access    TEXT NOT NULL,
	real_refresh   TEXT NOT NULL,
	endpoint       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS token_by_refresh ON token (issued_refresh);`

// tokenRow is one captured login. issued_* are the placeholders the client
// holds; real_* are the live tokens; endpoint is the token-endpoint identity
// that minted them (used to scope where the real access token may be injected).
type tokenRow struct {
	IssuedAccess  string
	IssuedRefresh string
	RealAccess    string
	RealRefresh   string
	Endpoint      string
}

// VaultStore is the SQLite-backed persistence for captured logins.
type VaultStore struct {
	db *sql.DB
}

// OpenVaultStore opens (creating if needed) the vault database at path. The
// file is forced to mode 0600 before SQLite touches it; SQLite copies that mode
// onto its journal/WAL files, so no transient world-readable token file is ever
// written. The single-connection pool serializes the store's infrequent writes.
func OpenVaultStore(path string) (*VaultStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating data directory for %s: %w", path, err)
	}
	// Pre-create with tight perms (WriteFile/OpenFile honour umask, so chmod
	// explicitly afterwards, like the CA key).
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating vault file %s: %w", path, err)
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("securing vault file %s: %w", path, err)
	}

	dsn := "file:" + url.PathEscape(path) + "?_pragma=busy_timeout(1000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening vault database %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(vaultSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initializing vault schema in %s: %w", path, err)
	}
	return &VaultStore{db: db}, nil
}

// GetByAccess finds the login a client is presenting on a resource request,
// matched by its placeholder access token. ok is false when the token is not
// one of crinj's placeholders.
func (s *VaultStore) GetByAccess(issuedAccess string) (tokenRow, bool, error) {
	return s.queryRow("issued_access = ?", issuedAccess)
}

// GetByRefresh finds the login a client is refreshing, matched by its
// placeholder refresh token. An empty key never matches (rows without a refresh
// token store the empty string).
func (s *VaultStore) GetByRefresh(issuedRefresh string) (tokenRow, bool, error) {
	if issuedRefresh == "" {
		return tokenRow{}, false, nil
	}
	return s.queryRow("issued_refresh = ?", issuedRefresh)
}

// queryRow runs a single-row lookup with a fixed WHERE clause (never user
// input) and one bound argument.
func (s *VaultStore) queryRow(where, arg string) (tokenRow, bool, error) {
	var r tokenRow
	err := s.db.QueryRow(
		`SELECT issued_access, issued_refresh, real_access, real_refresh, endpoint FROM token WHERE `+where,
		arg,
	).Scan(&r.IssuedAccess, &r.IssuedRefresh, &r.RealAccess, &r.RealRefresh, &r.Endpoint)
	if err == sql.ErrNoRows {
		return tokenRow{}, false, nil
	}
	if err != nil {
		return tokenRow{}, false, fmt.Errorf("loading token row: %w", err)
	}
	return r, true, nil
}

// Upsert writes a captured login, replacing any existing row with the same
// placeholder access token (a refresh keeps the placeholder and rotates the
// real tokens).
func (s *VaultStore) Upsert(r tokenRow) error {
	_, err := s.db.Exec(
		`INSERT INTO token (issued_access, issued_refresh, real_access, real_refresh, endpoint)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(issued_access) DO UPDATE SET
		   issued_refresh = excluded.issued_refresh,
		   real_access    = excluded.real_access,
		   real_refresh   = excluded.real_refresh,
		   endpoint       = excluded.endpoint`,
		r.IssuedAccess, r.IssuedRefresh, r.RealAccess, r.RealRefresh, r.Endpoint,
	)
	if err != nil {
		return fmt.Errorf("saving token row: %w", err)
	}
	return nil
}

// Close releases the database handle.
func (s *VaultStore) Close() error { return s.db.Close() }
