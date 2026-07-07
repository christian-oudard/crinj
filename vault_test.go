package main

import (
	"os"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *VaultStore {
	t.Helper()
	store, err := OpenVaultStore(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatalf("OpenVaultStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestVaultStoreUpsertGetByAccess(t *testing.T) {
	store := openTestStore(t)
	want := tokenRow{
		IssuedAccess:  "sk-ant-oat01-FAKE",
		IssuedRefresh: "sk-ant-ort01-FAKE",
		RealAccess:    "REAL-at",
		RealRefresh:   "REAL-rt",
		Endpoint:      "platform.claude.com /v1/oauth/token",
	}
	if err := store.Upsert(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.GetByAccess("sk-ant-oat01-FAKE")
	if err != nil || !ok {
		t.Fatalf("GetByAccess: ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestVaultStoreGetByRefresh(t *testing.T) {
	store := openTestStore(t)
	row := tokenRow{IssuedAccess: "AT", IssuedRefresh: "RT", RealRefresh: "real", Endpoint: "e"}
	store.Upsert(row)
	got, ok, _ := store.GetByRefresh("RT")
	if !ok || got.IssuedAccess != "AT" {
		t.Fatalf("GetByRefresh: ok=%v %+v", ok, got)
	}
	// empty refresh key never matches (rows without a refresh store "")
	if _, ok, _ := store.GetByRefresh(""); ok {
		t.Error("empty refresh should not match")
	}
}

func TestVaultStoreGetByIdentity(t *testing.T) {
	store := openTestStore(t)
	row := tokenRow{IssuedAccess: "AT", RealAccess: "real", Endpoint: "e", Identity: "e\x00iss\x00\x00scope"}
	store.Upsert(row)
	got, ok, err := store.GetByIdentity("e\x00iss\x00\x00scope")
	if err != nil || !ok || got.IssuedAccess != "AT" {
		t.Fatalf("GetByIdentity: ok=%v err=%v %+v", ok, err, got)
	}
	// empty identity never matches (OAuth rows store "")
	if _, ok, _ := store.GetByIdentity(""); ok {
		t.Error("empty identity should not match")
	}
}

func TestVaultStoreGetMissing(t *testing.T) {
	store := openTestStore(t)
	if _, ok, err := store.GetByAccess("nope"); ok || err != nil {
		t.Fatalf("expected absent, ok=%v err=%v", ok, err)
	}
}

func TestVaultStoreUpsertRotates(t *testing.T) {
	store := openTestStore(t)
	store.Upsert(tokenRow{IssuedAccess: "AT", RealAccess: "first", Endpoint: "e"})
	store.Upsert(tokenRow{IssuedAccess: "AT", RealAccess: "second", RealRefresh: "rt", Endpoint: "e"})
	got, _, _ := store.GetByAccess("AT")
	if got.RealAccess != "second" || got.RealRefresh != "rt" {
		t.Fatalf("rotate failed: %+v", got)
	}
}

// Two logins from one issuer coexist as separate rows.
func TestVaultStoreMultipleRowsPerEndpoint(t *testing.T) {
	store := openTestStore(t)
	store.Upsert(tokenRow{IssuedAccess: "AT1", RealAccess: "real1", Endpoint: "e"})
	store.Upsert(tokenRow{IssuedAccess: "AT2", RealAccess: "real2", Endpoint: "e"})
	a, _, _ := store.GetByAccess("AT1")
	b, _, _ := store.GetByAccess("AT2")
	if a.RealAccess != "real1" || b.RealAccess != "real2" {
		t.Fatalf("rows collided: %+v %+v", a, b)
	}
}

// The whole point: rows written by one process are visible to the next.
func TestVaultStoreSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.db")
	store, err := OpenVaultStore(path)
	if err != nil {
		t.Fatal(err)
	}
	store.Upsert(tokenRow{IssuedAccess: "AT", RealAccess: "REAL-at", Endpoint: "e"})
	store.Close()

	reopened, err := OpenVaultStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, ok, _ := reopened.GetByAccess("AT")
	if !ok || got.RealAccess != "REAL-at" {
		t.Fatalf("row did not survive reopen: ok=%v %+v", ok, got)
	}
}

func TestVaultStoreFileIs0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.db")
	store, err := OpenVaultStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("vault file mode = %o, want 600", perm)
	}
}
