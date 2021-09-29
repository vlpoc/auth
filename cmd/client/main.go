package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"

	auth "github.com/vlpoc/auth"

	authproto "github.com/vlpoc/proto/auth"
)

func main() {
	keypath := "/Users/kyle.nusbaum/Documents/CodeBase/vlpoc-auth/cmd/authsrv/kyle.priv.pem"
	privPem, err := ioutil.ReadFile(keypath)
	if err != nil {
		log.Printf("Failed to read %s: %s", keypath, err)
		return
	}
	//pub, err := pem.D
	privBlock, _ := pem.Decode(privPem)
	if privBlock == nil {
		log.Printf("Failed to decrypt %s. No PEM block.", keypath)
		return
	}
	if privBlock.Type != "RSA PRIVATE KEY" {
		log.Printf("Failed to validate %s: type = %s", keypath, privBlock.Type)
		return
	}
	rsaprivkey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		log.Printf("Failed to parse PKCS1 Private Key %s: %s", keypath, err)
		return
	}

	cert, err := auth.AuthenticateRSA("localhost:8181", rsaprivkey, &authproto.Actor{Name: "kyle", Domain: "users"})
	if err != nil {
		log.Printf("Failed auth: %s", err)
		return
	}
	log.Printf("received cert for actor: %s", cert.Actor.ActorString())

	err = auth.Validate(cert)
	if err != nil {
		log.Printf("Failed to validate cert: %s", err)
		return
	}
}
