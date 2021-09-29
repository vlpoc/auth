package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"

	authproto "github.com/vlpoc/proto/auth"
	"google.golang.org/grpc"
)

func NewAuthSrv(keydir, address string) (*AuthSrv, error) {
	domains, err := os.ReadDir(keydir)
	if err != nil {
		return nil, err
	}
	keys := make(map[Domain]map[ActorName]*rsa.PublicKey)
	for _, d := range domains {
		if !d.IsDir() {
			continue
		}
		dname := d.Name()
		names, ok := keys[Domain(dname)]
		if !ok {
			names = make(map[ActorName]*rsa.PublicKey)
			keys[Domain(dname)] = names
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
			names[ActorName(name)] = rsapubkey
			log.Printf("Loaded %s/%s@%s", name, dname, address)
		}
	}
	pk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Printf("Failed to generate private key: %s", err)
		return nil, err
	}
	return &AuthSrv{
		Key:     pk,
		Keys:    keys,
		Address: address,
	}, nil
}

var (
	keypath  string
	hostname string
	port     int
)

func init() {
	flag.StringVar(&keypath, "keypath", "", "The path to the directory containing keys for the authsrv users.")
	flag.StringVar(&hostname, "hostname", "", "The fqdn at which this authsrv can be reached. Used for the Authenticator field in the Actor message.")
	flag.IntVar(&port, "port", 8181, "The port on which authsrv will listen. Added to hostname to create the Authenticator field.")
	flag.Parse()
}

func main() {
	if keypath == "" {
		log.Printf("Must specify keypath.")
		flag.Usage()
		os.Exit(1)
	}
	if hostname == "" {
		log.Printf("Must specify hostname.")
		flag.Usage()
		os.Exit(1)
	}

	//srv, err := NewAuthSrv("/Users/kyle.nusbaum/Documents/CodeBase/vlpoc-auth/cmd/authsrv/keys", "localhost:8181")
	srv, err := NewAuthSrv(keypath, fmt.Sprintf("%s:%d", hostname, port))
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	authproto.RegisterAuthServer(grpcServer, srv)
	grpcServer.Serve(lis)
}
