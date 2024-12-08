package nametocert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

type Context struct {
	m certsMap
}

func (c *Context) Add(cert *tls.Certificate) error {
	if cert == nil {
		return errors.New("nametocert context add error: cert is nil")
	}
	if len(cert.Certificate) == 0 {
		return errors.New("nametocert context add error: len(cert.Certificate) == 0")
	}

	xc, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	// domain name
	for _, name := range xc.DNSNames {
		c.m[name] = cert
	}
	// IP (no SNI)
	if len(xc.IPAddresses) != 0 {
		c.m[""] = cert
	}
	return nil
}

func (c *Context) SetDefault(cert *tls.Certificate) {
	if cert != nil {
		c.m["*"] = cert
	} else {
		delete(c.m, "*")
	}
}
