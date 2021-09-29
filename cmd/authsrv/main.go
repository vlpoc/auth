package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"

	"github.com/vlpoc/auth"
	"google.golang.org/grpc"
)

func NewAuthSrv(keydir, address string) (*auth.AuthSrv, error) {
	domains, err := os.ReadDir(keydir)
	if err != nil {
		return nil, err
	}
	keys := make(map[auth.Domain]map[auth.ActorName]*rsa.PublicKey)
	for _, d := range domains {
		if !d.IsDir() {
			continue
		}
		dname := d.Name()
		names, ok := keys[auth.Domain(dname)]
		if !ok {
			names = make(map[auth.ActorName]*rsa.PublicKey)
			keys[auth.Domain(dname)] = names
		}
		namedir := path.Join(keydir, dname)
		ns, err := os.ReadDir(namedir)
		if err != nil {
			return nil, err
		}
		for _, n := range ns {
			name := n.Name()
			if name == "groups" {
				// TODO: implement groups
				continue
			}
			keypath := path.Join(namedir, name)
			pubPem, err := ioutil.ReadFile(keypath)
			if err != nil {
				log.Printf("Failed to read %s: %s", keypath, err)
				continue
			}
			//pub, err := pem.D
			pubBlock, _ := pem.Decode(pubPem)
			if pubBlock == nil {
				log.Printf("Failed to decrypt %s. No PEM block.", keypath)
				continue
			}
			if pubBlock.Type != "RSA PUBLIC KEY" {
				log.Printf("Failed to validate %s: type = %s", keypath, pubBlock.Type)
				continue
			}
			rsapubkey, err := x509.ParsePKCS1PublicKey(pubBlock.Bytes)
			if err != nil {
				log.Printf("Failed to parse PKCS1 Public Key %s: %s", keypath, err)
				continue
			}
			// 			if rsapubkey.Size() < 4096 {
			// 				log.Printf("Failed to load Public Key %s: Key size is %d, less than the required 4096.", keypath, rsapubkey.Size())
			// 			}
			names[auth.ActorName(name)] = rsapubkey
			log.Printf("Loaded %s/%s@%s", name, dname, address)
		}
	}
	pk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("Failed to generate private key: %s", err)
		return nil, err
	}
	return &auth.AuthSrv{
		Key:     pk,
		Keys:    keys,
		Address: address,
	}, nil
}

func main() {
	srv, err := NewAuthSrv("/Users/kyle.nusbaum/Documents/CodeBase/vlpoc-auth/cmd/authsrv/keys", "localhost:8181")
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("localhost:8181"))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	//log.Printf("Actor: [%s]", &auth.Actor{Name: "kyle", Domain: "users", Authenticator: "localhost:8181"})

	grpcServer := grpc.NewServer()
	auth.RegisterAuthServer(grpcServer, srv)
	grpcServer.Serve(lis)
}
