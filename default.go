package nametocert

import (
	"crypto/tls"
	_ "embed"
	"sync"
)

//go:embed default.crt
var fileCrt string

//go:embed default.key
var fileKey string

var defaultCert *tls.Certificate

var defaultCertSyncOnce sync.Once

func GetDefaultCert() *tls.Certificate {
	defaultCertSyncOnce.Do(func() {
		cert, _ := tls.X509KeyPair([]byte(fileCrt), []byte(fileKey))
		defaultCert = &cert
	})
	return defaultCert
}
