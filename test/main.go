package main

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/bddjr/nametocert-go"
)

var certsProc = &nametocert.Processor{
	// SSL Reject Handshake
	RejectHandshakeIfUnrecognizedName: true,
}

func updateCert() error {
	certs := nametocert.Certs{}

	cert, err := tls.LoadX509KeyPair("localhost.crt", "localhost.key")
	if err != nil {
		return err
	}
	certs.Add(&cert)

	// Hot Update Certificate
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
