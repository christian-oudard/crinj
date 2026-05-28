package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA returns a fresh in-memory CA for tests.
func testCA(t *testing.T) *CertificateAuthority {
	t.Helper()
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	return ca
}

func TestCAGeneratesValidSelfSignedCert(t *testing.T) {
	ca := testCA(t)
	if len(ca.caCertDER) == 0 {
		t.Fatal("CA cert DER is empty")
	}
	pem := ca.CACertPEM()
	if !strings.HasPrefix(pem, "-----BEGIN CERTIFICATE-----") {
		t.Errorf("missing BEGIN marker")
	}
	if !strings.Contains(pem, "-----END CERTIFICATE-----") {
		t.Errorf("missing END marker")
	}
}

func TestCAPEMRoundTripsDER(t *testing.T) {
	ca := testCA(t)
	block, _ := pem.Decode([]byte(ca.CACertPEM()))
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	if !bytes.Equal(block.Bytes, ca.caCertDER) {
		t.Error("PEM-decoded DER does not match original CA cert DER")
	}
}

func TestDerToPEMRoundTrips(t *testing.T) {
	ca := testCA(t)
	encoded := derToPEM(ca.caCertDER)
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		t.Fatal("pem.Decode returned nil")
	}
	if !bytes.Equal(block.Bytes, ca.caCertDER) {
		t.Error("round-trip DER mismatch")
	}
}

func TestDerToPEMHas64CharLines(t *testing.T) {
	ca := testCA(t)
	pemStr := derToPEM(ca.caCertDER)
	for _, line := range strings.Split(strings.TrimRight(pemStr, "\n"), "\n") {
		if strings.HasPrefix(line, "-----") {
			continue
		}
		if len(line) > 64 {
			t.Errorf("PEM body line too long (%d): %q", len(line), line)
		}
	}
}

func TestCACertSubjectCN(t *testing.T) {
	ca := testCA(t)
	if cn := ca.caCert.Subject.CommonName; cn != localCACN {
		t.Errorf("CN=%q want %q", cn, localCACN)
	}
	orgs := ca.caCert.Subject.Organization
	if len(orgs) != 1 || orgs[0] != "Crinj" {
		t.Errorf("org=%v want [Crinj]", orgs)
	}
}

func TestCACertIsCAWithCorrectKeyUsage(t *testing.T) {
	ca := testCA(t)
	if !ca.caCert.IsCA {
		t.Error("CA cert IsCA=false")
	}
	if !ca.caCert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid=false")
	}
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if ca.caCert.KeyUsage != want {
		t.Errorf("KeyUsage=%v want %v", ca.caCert.KeyUsage, want)
	}
}

// ── Leaf cert tests ────────────────────────────────────────────────────

func TestLeafCertGeneratesValidServerConfig(t *testing.T) {
	ca := testCA(t)
	cfg, err := ca.ServerConfigForHost("example.com")
	if err != nil {
		t.Fatalf("ServerConfigForHost: %v", err)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos=%v want [http/1.1]", cfg.NextProtos)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len=%d want 1", len(cfg.Certificates))
	}
	chain := cfg.Certificates[0].Certificate
	if len(chain) != 2 {
		t.Errorf("chain len=%d want 2 (leaf + ca)", len(chain))
	}
	// CA cert is the second element of the chain.
	if !bytes.Equal(chain[1], ca.caCertDER) {
		t.Error("chain[1] != ca cert DER")
	}
}

func TestLeafCertDifferentHostnamesProduceDistinctConfigs(t *testing.T) {
	ca := testCA(t)
	a, err := ca.ServerConfigForHost("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.ServerConfigForHost("b.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("expected distinct *tls.Config objects")
	}
	if bytes.Equal(a.Certificates[0].Certificate[0], b.Certificates[0].Certificate[0]) {
		t.Error("leaf DERs should differ between hostnames")
	}
}

func TestLeafCertContainsAuthorityKeyIdentifier(t *testing.T) {
	ca := testCA(t)
	cfg, err := ca.ServerConfigForHost("aki-test.example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf := cfg.Certificates[0].Certificate[0]
	// OID 2.5.29.35 (authorityKeyIdentifier) DER prefix: 06 03 55 1d 23
	akiOID := []byte{0x55, 0x1d, 0x23}
	if !bytes.Contains(leaf, akiOID) {
		t.Error("leaf certificate must contain Authority Key Identifier extension (OID 2.5.29.35)")
	}
}

func TestLeafCertParsesAndContainsHostname(t *testing.T) {
	ca := testCA(t)
	cfg, err := ca.ServerConfigForHost("example.com")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN=%q want example.com", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames=%v", leaf.DNSNames)
	}
}

// ── Disk persistence ───────────────────────────────────────────────────

func TestCAPersistsAndLoadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	ca1, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrGenerateCA: %v", err)
	}
	ca2, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrGenerateCA: %v", err)
	}
	if ca1.CACertPEM() != ca2.CACertPEM() {
		t.Error("re-loaded CA cert PEM differs from original")
	}
	if !bytes.Equal(ca1.caCertDER, ca2.caCertDER) {
		t.Error("re-loaded CA cert DER differs from original")
	}
}

func TestCAKeyFileHasRestrictedPermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	keyPath := filepath.Join(dir, "gateway", "ca.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("ca.key perm=%o want 0600", mode)
	}
}

func TestLeafSignedByPersistedCAIsValid(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrGenerateCA(dir); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	ca, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	cfg, err := ca.ServerConfigForHost("test.example.com")
	if err != nil {
		t.Fatalf("ServerConfigForHost: %v", err)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "http/1.1" {
		t.Errorf("NextProtos=%v", cfg.NextProtos)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	// Verify the leaf chains to the persisted CA.
	roots := x509.NewCertPool()
	roots.AddCert(ca.caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		DNSName:     "test.example.com",
		CurrentTime: time.Now(),
	}); err != nil {
		t.Errorf("leaf.Verify against reloaded CA failed: %v", err)
	}
}

func TestCALoadFromEnvVars(t *testing.T) {
	// Generate a CA, dump key+cert to PEM, set env vars, reload.
	src, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(src.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	t.Setenv("GATEWAY_CA_KEY", string(keyPEM))
	t.Setenv("GATEWAY_CA_CERT", src.CACertPEM())

	dir := t.TempDir()
	loaded, err := LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	if !bytes.Equal(loaded.caCertDER, src.caCertDER) {
		t.Error("env-loaded CA cert DER differs from source")
	}
	// No files should have been written.
	if _, err := os.Stat(filepath.Join(dir, "gateway")); err == nil {
		t.Error("env-mode load should not create gateway dir")
	}
}

// ── Leaf cache ─────────────────────────────────────────────────────────

func TestLeafCacheReturnsSameConfigWithinValidity(t *testing.T) {
	ca := testCA(t)
	a, err := ca.ServerConfigForHost("cached.example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ca.ServerConfigForHost("cached.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Error("expected cache hit (same *tls.Config pointer)")
	}
}

func TestLeafCertHandlesIPAddressHostname(t *testing.T) {
	ca := testCA(t)
	cfg, err := ca.ServerConfigForHost("10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.1" {
		t.Errorf("IPAddresses=%v want [10.0.0.1]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames should be empty for IP-only host, got %v", leaf.DNSNames)
	}
}
