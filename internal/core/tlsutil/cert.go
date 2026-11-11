// Package tlsutil loads the phishing portal certificate, generating a
// self-signed one when the operator has not supplied a real certificate.
//
// A strict AI agent or HTTP client refuses a self-signed certificate, so the
// generated leaf carries the configured portal domain in its SANs instead of a
// placeholder name. For a production domain, drop a real certificate into
// CertDir and it will be selected by SNI; nothing else needs to change.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// LoadOrGenerateFor loads the certificate/key pair at the given paths, or
// creates a self-signed ECDSA certificate there. Names are added to the SANs.
func LoadOrGenerateFor(certFile, keyFile string, names []string) (tls.Certificate, error) {
	if fileExists(certFile) && fileExists(keyFile) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
		}
		return cert, nil
	}
	return generate(certFile, keyFile, names)
}

func generate(certFile, keyFile string, names []string) (tls.Certificate, error) {
	if err := os.MkdirAll(filepath.Dir(certFile), 0o750); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o750); err != nil {
		return tls.Certificate{}, err
	}

	dnsNames, ips := certificateNames(names)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	commonName := "phishsim.local"
	for _, n := range dnsNames {
		if !strings.HasPrefix(n, "*.") {
			commonName = n
			break
		}
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"PhishTide Training"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// certificateNames merges operator-supplied names with the always-present
// loopback names, rejecting anything that is not a DNS name or IP.
func certificateNames(extra []string) ([]string, []net.IP) {
	var (
		dns []string
		ips []net.IP
	)
	seenDNS := map[string]bool{}
	seenIP := map[string]bool{}
	add := func(raw string) {
		n := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
		if n == "" {
			return
		}
		if ip := net.ParseIP(n); ip != nil {
			if !seenIP[ip.String()] {
				seenIP[ip.String()] = true
				ips = append(ips, ip)
			}
			return
		}
		if !validDNSName(n) {
			return
		}
		if !seenDNS[n] {
			seenDNS[n] = true
			dns = append(dns, n)
		}
	}
	// Operator-supplied names come first so the leaf's common name is the
	// configured portal domain rather than a built-in loopback name. Loopback is
	// always present for local operator access.
	for _, n := range extra {
		add(n)
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")
	if len(dns) == 0 {
		dns = append(dns, "phishsim.local")
	}
	return dns, ips
}

var dnsNameRe = regexp.MustCompile(`^(\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)

func validDNSName(n string) bool {
	if len(n) > 253 {
		return false
	}
	return dnsNameRe.MatchString(n)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
