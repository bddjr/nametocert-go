package nametocert

import (
	"crypto/tls"
	"embed"
)

//go:embed localhost.crt
//go:embed localhost.key
var defaultCertFiles embed.FS

var defaultCert *tls.Certificate

func getDefaultCert() *tls.Certificate {
	if defaultCert == nil {
		crt, _ := defaultCertFiles.ReadFile("localhost.crt")
		key, _ := defaultCertFiles.ReadFile("localhost.key")
		cert, _ := tls.X509KeyPair(crt, key)
		defaultCert = &cert
	}
	return defaultCert
}
