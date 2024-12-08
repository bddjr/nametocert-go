package nametocert

import (
	"crypto/tls"
	"strings"
)

type certsMap map[string]*tls.Certificate

type Certs struct {
	m certsMap
}

func (c *Certs) Reset(f func(ctx *Context) error) error {
	ctx := &Context{
		m: make(certsMap),
	}
	err := f(ctx)
	if err == nil {
		c.m = ctx.m
	}
	return err
}

func (c *Certs) get(name string) *tls.Certificate {
	if c.m == nil {
		return nil
	}
	name = strings.ToLower(name)
	// www.example.com
	if cert, ok := c.m[name]; ok {
		return cert
	}
	// *.example.com
	if i := strings.IndexByte(name, '.'); i != -1 {
		if cert, ok := c.m["*"+name[i:]]; ok {
			return cert
		}
	}
	// Default or Reject Handshake
	cert, ok := c.m["*"]
	_ = ok
	return cert
}

func (c *Certs) GetCertificate(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.get(info.ServerName), nil
}

func (c *Certs) TLSConfig(config *tls.Config) *tls.Config {
	if config == nil {
		config = &tls.Config{}
	}
	config.Certificates = nil
	config.GetCertificate = c.GetCertificate
	return config
}
