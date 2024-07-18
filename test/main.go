package main

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/bddjr/nametocert-go"
)

func main() {
	fmt.Print("\n" +
		"  Accept: https://www.localhost:5678\n" +
		"  Accept: https://localhost:5678\n" +
		"  Reject: https://127.0.0.1:5678\n" +
		"\n",
	)

	certs := make([]*tls.Certificate, 1)
	cert, err := tls.LoadX509KeyPair("localhost.crt", "localhost.key")
	if err != nil {
		panic(err)
	}
	certs[0] = &cert

	nameToCertConf := nametocert.New(certs)

	// SSL Reject Handshake
	nameToCertConf.RejectHandshakeIfUnrecognizedName = true

	// Hot Update Certificate
	// nameToCertConf.Reset(certs)

	srv := &http.Server{
		Addr: ":5678",
		TLSConfig: &tls.Config{
			GetCertificate: nameToCertConf.GetCertificate,
		},
	}
	err = srv.ListenAndServeTLS("", "")
	fmt.Println(err)
}
