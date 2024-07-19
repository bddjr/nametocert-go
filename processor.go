package nametocert

import (
	"crypto/tls"
	"strings"
)

type Processor struct {
	certs Certs

	// If the name cannot be recognized, reject the handshake.
	// This option does not support hot updates.
	RejectHandshakeIfUnrecognizedName bool

	// If nil, use the built-in certificate
	DefaultCert *tls.Certificate
}

func NewProcessor(certs Certs) *Processor {
	return &Processor{
		certs: certs,
	}
}

func (c *Processor) SetCerts(certs Certs) {
	c.certs = certs
}

func (c *Processor) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.certs != nil {
		// www.example.com
		if cert, ok := c.certs[info.ServerName]; ok {
			return cert, nil
		}
		// *.example.com
		if i := strings.IndexByte(info.ServerName, '.'); i != -1 {
			if cert, ok := c.certs["*"+info.ServerName[i:]]; ok {
				return cert, nil
			}
		}
	}
	// Reject Handshake
	if c.RejectHandshakeIfUnrecognizedName {
		return nil, nil
	}
	// Default
	if c.DefaultCert != nil {
		return c.DefaultCert, nil
	}
	return GetDefaultCert(), nil
}
