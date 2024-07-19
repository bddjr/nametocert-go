package nametocert

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
	"sync"
)

type Certs map[string]*tls.Certificate

func (c Certs) Add(cert *tls.Certificate) error {
	xc, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	// domain name
	for _, name := range xc.DNSNames {
		c[name] = cert
	}
	// ip (no SNI)
	if len(xc.IPAddresses) > 0 {
		c[""] = cert
	}
	return nil
}

//go:embed default.crt
//go:embed default.key
var defaultCertFiles embed.FS

var defaultCert *tls.Certificate
var defaultCertSyncOnce sync.Once

func GetDefaultCert() *tls.Certificate {
	defaultCertSyncOnce.Do(func() {
		crt, _ := defaultCertFiles.ReadFile("default.crt")
		key, _ := defaultCertFiles.ReadFile("default.key")
		cert, _ := tls.X509KeyPair(crt, key)
		defaultCert = &cert
	})
	return defaultCert
}
