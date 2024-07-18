package nametocert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
)

type Conf struct {
	NameToCert map[string]*tls.Certificate

	// If the name cannot be recognized, reject handshake
	RejectHandshakeIfUnrecognizedName bool
}

func New(Certs []*tls.Certificate) *Conf {
	c := &Conf{}
	c.Reset(Certs)
	return c
}

func (c *Conf) Reset(Certs []*tls.Certificate) {
	ntc := map[string]*tls.Certificate{}
	for _, cert := range Certs {
		xc, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			panic(err)
		}
		// domain name
		for _, name := range xc.DNSNames {
			ntc[name] = cert
		}
		// ip (no SNI)
		if len(xc.IPAddresses) > 0 {
			ntc[""] = cert
		}
	}
	c.NameToCert = ntc
}

func (c *Conf) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.NameToCert != nil {
		// www.example.com
		if cert, ok := c.NameToCert[info.ServerName]; ok {
			return cert, nil
		}
		// *.example.com
		if i := strings.IndexByte(info.ServerName, '.'); i != -1 {
			if cert, ok := c.NameToCert["*"+info.ServerName[i:]]; ok {
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
		return nil, errors.New("nametocert: unrecognized name")
	}
	// Default
	return getDefaultCert(), nil
}
