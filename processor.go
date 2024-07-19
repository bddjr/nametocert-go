package nametocert

import (
	"crypto/tls"
	"errors"
	"strings"
)

var ErrUnrecognizedName = errors.New("nametocert: unrecognized name")

type Processor struct {
	// If the name cannot be recognized, reject handshake
	RejectHandshakeIfUnrecognizedName bool

	// If nil, use the built-in certificate
	DefaultCert *tls.Certificate

	certs Certs
}

func NewProcessor(certs Certs) *Processor {
	return &Processor{
		certs: certs,
	}
}

func (c *Processor) Set(certs Certs) {
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
		info.Conn.Write([]byte{
			// Content Type: Alert
			21,
			// Version: TLS 1.2
			3, 3,
			// Length: 2
			0, 2,
			// Alert Message Level: Fatal
			2,
			// Alert Message Description: Unrecognized Name
			112,
		})
		info.Conn.Close()
		return nil, ErrUnrecognizedName
	}
	// Default
	if c.DefaultCert != nil {
		return c.DefaultCert, nil
	}
	return GetDefaultCert(), nil
}
