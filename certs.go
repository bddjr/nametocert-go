package nametocert

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
)

type certsMap map[string]*tls.Certificate

type Certs struct {
	lockedCerts certsMap
	certs       certsMap

	// If nil, use the built-in certificate
	DefaultCert *tls.Certificate
}

func (c *Certs) Clear() {
	c.certs = certsMap{}
}

func (c *Certs) Add(cert *tls.Certificate) error {
	xc, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	// domain name
	for _, name := range xc.DNSNames {
		c.certs[name] = cert
	}
	// IP (no SNI)
	if len(xc.IPAddresses) > 0 {
		c.certs[""] = cert
	}
	return nil
}

func (c *Certs) CompleteUpdate() {
	c.lockedCerts = c.certs
	c.Clear()
}

// If the name cannot be recognized, reject the handshake.
func (c *Certs) GetCert_DefaultReject(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// www.example.com
	if cert, ok := c.lockedCerts[info.ServerName]; ok {
		return cert, nil
	}
	// *.example.com
	if i := strings.IndexByte(info.ServerName, '.'); i != -1 {
		if cert, ok := c.lockedCerts["*"+info.ServerName[i:]]; ok {
			return cert, nil
		}
	}
	// Reject Handshake
	return nil, nil
}

// If the name cannot be recognized, return the default certificate.
func (c *Certs) GetCert_DefaultCert(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, _ := c.GetCert_DefaultReject(info)
	if cert != nil {
		return cert, nil
	}
	// Default
	if c.DefaultCert != nil {
		return c.DefaultCert, nil
	}
	return GetDefaultCert(), nil
}
