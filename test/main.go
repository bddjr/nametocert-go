package main

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/bddjr/nametocert-go"
)

var certs nametocert.Certs

// This option does not support hot update,
// please restart the HTTPS server after changing it.
var enableRejectHandshakeIfUnrecognizedName = true

func updateCert() error {
	// Clear
	certs.Clear()

	// Add
	cert, err := tls.LoadX509KeyPair("localhost.crt", "localhost.key")
	if err != nil {
		return err
	}
	certs.Add(&cert)

	// Hot Update Certificates
	certs.CompleteUpdate()

	return nil
}

func main() {
	fmt.Print("\n" +
		"  Accept: https://www.localhost:5678\n" +
		"  Accept: https://localhost:5678\n" +
		"  Reject: https://127.0.0.1:5678\n" +
		"\n",
	)

	err := updateCert()
	if err != nil {
		panic(err)
	}

	srv := &http.Server{
		Addr: ":5678",
		TLSConfig: &tls.Config{
			Certificates: nil,
		},
	}

	// This option does not support hot update,
	// please restart the HTTPS server after changing it.
	if enableRejectHandshakeIfUnrecognizedName {
		srv.TLSConfig.GetCertificate = certs.GetCert_DefaultReject
	} else {
		srv.TLSConfig.GetCertificate = certs.GetCert_DefaultCert
	}

	err = srv.ListenAndServeTLS("", "")
	fmt.Println(err)
}
