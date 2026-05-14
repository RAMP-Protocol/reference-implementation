package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
)

// rsaPublicKeyHandler serves the current demo RSA public key in PEM form so
// a local CloudFront-compatible verifier can bootstrap without AWS creds.
// Unauth, demo-only; production routes this via IAM + Secrets Manager.
func rsaPublicKeyHandler(pub *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_ = pem.Encode(w, &pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
}
