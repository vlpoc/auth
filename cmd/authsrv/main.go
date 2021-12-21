package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"

	"github.com/vlpoc/proto/authpb"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
)

var port = 8181

func main() {
	log.Printf("Starting authsrv...")
	dir, err := os.UserConfigDir()
	if err != nil {
		log.Fatalf("Could not locate authsrv config dir: %s", err)
	}
	authdir := path.Join(dir, "vlpoc-authsrv")
	err = os.MkdirAll(authdir, 0700)
	if err != nil {
		log.Fatalf("Failed to create authdir %s: %s", authdir, err)
	}
	authSrv, err := NewAuthSrv(authdir, "vlpoc.com")
	if err != nil {
		log.Fatalf("Failed to start authsrv: %s", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("hello"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to generate test user: %s", err)
	}
	authSrv.hashes["kyle"] = hash

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(authSrv.credentials()))
	authpb.RegisterAuthServer(grpcServer, authSrv)
	grpcServer.Serve(lis)
}
