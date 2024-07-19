package main

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/bddjr/nametocert-go"
)

var certsProc nametocert.Processor

func updateCert() error {
	certs := nametocert.Certs{}

	cert, err := tls.LoadX509KeyPair("localhost.crt", "localhost.key")
	if err != nil {
		return err
	}
	certs.Add(&cert)

	// Hot Update Certificates
	certsProc.SetCerts(certs)

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

	// If the name cannot be recognized, reject the handshake.
	// This option does not support hot updates.
	// If you change this option, please restart the HTTPS server.
	certsProc.RejectHandshakeIfUnrecognizedName = true

	srv := &http.Server{
		Addr: ":5678",
		TLSConfig: &tls.Config{
			Certificates:   nil,
			GetCertificate: certsProc.GetCertificate,
		},
	}
	err = srv.ListenAndServeTLS("", "")
	fmt.Println(err)
}
