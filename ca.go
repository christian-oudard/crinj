package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Certificate Authority management for MITM TLS interception.
//
// Generates and persists a self-signed CA, then signs per-hostname leaf certs
// on the fly so the gateway can terminate TLS with clients while forwarding to
// the real upstream.

const localCACN = "Crinj Local CA"

// neverExpires is the RFC 5280 §4.1.2.5 sentinel for certs with no
// well-defined expiration. Leaf private keys live only in this process and
// the CA root is installed only in the local cave trust store, so cert
// expiry buys nothing here and previously caused false-positive "expired"
// errors on long-running sessions and after suspend/NTP clock jumps.
var neverExpires = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// CertificateAuthority is the in-process CA. It is safe for concurrent use.
type CertificateAuthority struct {
	caCert    *x509.Certificate
	caCertDER []byte
	caKey     *ecdsa.PrivateKey

	cacheMu   sync.Mutex
	leafCache map[string]*tls.Config
}

// LoadOrGenerateCA loads the CA from environment variables, then disk, or
// generates and persists a fresh one.
//
// Priority:
//  1. GATEWAY_CA_KEY + GATEWAY_CA_CERT env vars (cloud / injected secrets).
//  2. Files at <data_dir>/gateway/ca.key and ca.pem (OSS / persisted on disk).
//  3. Generate a new CA and persist to disk (first startup).
func LoadOrGenerateCA(dataDir string) (*CertificateAuthority, error) {
	keyEnv := strings.TrimSpace(os.Getenv("GATEWAY_CA_KEY"))
	certEnv := strings.TrimSpace(os.Getenv("GATEWAY_CA_CERT"))
	if keyEnv != "" && certEnv != "" {
		slog.Info("loading CA from environment variables")
		return loadCAFromPEM(keyEnv, certEnv)
	}

	gatewayDir := filepath.Join(dataDir, "gateway")
	keyPath := filepath.Join(gatewayDir, "ca.key")
	certPath := filepath.Join(gatewayDir, "ca.pem")

	if fileExists(keyPath) && fileExists(certPath) {
		slog.Info("loading existing CA", "gateway_dir", gatewayDir)
		return loadCAFromDisk(keyPath, certPath)
	}

	slog.Info("generating new CA", "gateway_dir", gatewayDir)
	if err := os.MkdirAll(gatewayDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating gateway data directory: %w", err)
	}
	return generateAndPersistCA(keyPath, certPath)
}

// loadCAFromPEM parses a key+cert pair from PEM strings and returns a CA.
func loadCAFromPEM(keyPEM, certPEM string) (*CertificateAuthority, error) {
	keyPEM = strings.TrimSpace(keyPEM)
	certPEM = strings.TrimSpace(certPEM)

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("parsing CA private key: no PEM block found")
	}
	priv, err := parseECDSAKey(keyBlock)
	if err != nil {
		return nil, fmt.Errorf("parsing CA private key: %w", err)
	}

	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("no certificate found in CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}

	return &CertificateAuthority{
		caCert:    caCert,
		caCertDER: certBlock.Bytes,
		caKey:     priv,
		leafCache: map[string]*tls.Config{},
	}, nil
}

func loadCAFromDisk(keyPath, certPath string) (*CertificateAuthority, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA private key: %w", err)
	}
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}
	return loadCAFromPEM(string(keyBytes), string(certBytes))
}

func generateAndPersistCA(keyPath, certPath string) (*CertificateAuthority, error) {
	ca, err := generateCA()
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("writing CA private key: %w", err)
	}
	// WriteFile honours umask; force the perms explicitly.
	if err := os.Chmod(keyPath, 0o600); err != nil {
		return nil, fmt.Errorf("chmod CA private key: %w", err)
	}
	if err := os.WriteFile(certPath, []byte(ca.CACertPEM()), 0o644); err != nil {
		return nil, fmt.Errorf("writing CA certificate: %w", err)
	}
	slog.Info("generated and persisted new CA",
		"cn", localCACN, "key", keyPath, "cert", certPath)
	return ca, nil
}

// parseECDSAKey accepts a PEM block holding either a PKCS#8 ("PRIVATE KEY")
// or SEC 1 ("EC PRIVATE KEY") encoded ECDSA key.
func parseECDSAKey(block *pem.Block) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		priv, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not ECDSA (got %T)", k)
		}
		return priv, nil
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a valid ECDSA private key: %w", err)
	}
	return priv, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// generateCA produces a new self-signed ECDSA P-256 CA in memory.
func generateCA() (*CertificateAuthority, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key pair: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   localCACN,
			Organization: []string{"Crinj"},
		},
		NotBefore:             now,
		NotAfter:              neverExpires,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("self-signing CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("re-parsing CA certificate: %w", err)
	}
	return &CertificateAuthority{
		caCert:    caCert,
		caCertDER: caCertDER,
		caKey:     priv,
		leafCache: map[string]*tls.Config{},
	}, nil
}

// CACertPEM returns the CA cert as a PEM string. Used by agents to install
// the CA in their trust store.
func (ca *CertificateAuthority) CACertPEM() string {
	return derToPEM(ca.caCertDER)
}

// ServerConfigForHost returns a *tls.Config ready for a TLS handshake with a
// client requesting `hostname`. Leaves are minted once per hostname and
// reused for the lifetime of the process.
func (ca *CertificateAuthority) ServerConfigForHost(hostname string) (*tls.Config, error) {
	ca.cacheMu.Lock()
	if cfg, ok := ca.leafCache[hostname]; ok {
		ca.cacheMu.Unlock()
		return cfg, nil
	}
	ca.cacheMu.Unlock()

	cfg, err := ca.generateLeaf(hostname)
	if err != nil {
		return nil, err
	}

	ca.cacheMu.Lock()
	ca.leafCache[hostname] = cfg
	ca.cacheMu.Unlock()
	return cfg, nil
}

// generateLeaf signs a per-hostname leaf certificate and packages it into a
// *tls.Config offering both HTTP/2 and HTTP/1.1 via ALPN. The client picks;
// the MITM loop serves whichever it chose (h2 clients like gRPC need h2).
func (ca *CertificateAuthority) generateLeaf(hostname string) (*tls.Config, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key pair: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		// Backdate slightly to tolerate client clock skew.
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    neverExpires,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, ca.caCert, &leafKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing leaf certificate: %w", err)
	}
	cert := tls.Certificate{
		Certificate: [][]byte{leafDER, ca.caCertDER},
		PrivateKey:  leafKey,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// derToPEM encodes raw DER bytes as a PEM-formatted certificate string.
func derToPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
