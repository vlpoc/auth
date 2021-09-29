package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"

	"github.com/vlpoc/auth"
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

	cert, err := auth.AuthenticateRSA("localhost:8181", rsaprivkey, &auth.Actor{Name: "kyle", Domain: "users"})
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

	// 	conn, err := grpc.Dial("localhost:8181", grpc.WithInsecure())
	// 	if err != nil {
	// 		log.Printf("Failed to dial auth: %s", err)
	// 		return
	// 	}
	// 	defer conn.Close()
	// 	cli := auth.NewAuthClient(conn)
	// 	cert, err := auth.PerformAuthentication(cli, rsaprivkey, &auth.Actor{Name: "kyle", Domain: "users"})
	// 	if err != nil {
	// 		log.Printf("Failed to authenticate: %s", err)
	// 		return
	// 	}
	// 	log.Printf("Cert: %v", cert)
	//
	// 	//cert.Actor.Name = "jake"
	//
	// 	size := len(cert.Actor.Name) + len(cert.Actor.Domain) + len(cert.Actor.Authenticator) + 8 + len(cert.Nonce) + len(cert.Pubkey) + len(cert.Signature)
	// 	log.Printf("Cert Length: %d bytes", size)
	//
	// 	_, err = cli.Validate(context.Background(), cert)
	// 	if err != nil {
	// 		log.Printf("Failed to validate: %s", err)
	// 	} else {
	// 		log.Printf("Validated cert.")
	// 	}
}
