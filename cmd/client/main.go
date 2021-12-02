package main

import (
	"fmt"
	"os"

	"github.com/vlpoc/auth"
)

func main() {
	srv, err := auth.NewAuthSrv("localhost:8181", "/Users/kyle.nusbaum/Library/Application Support/vlpoc-authsrv/ca.crt.pem")
	if err != nil {
		fmt.Printf("Failed to create authsrv client: %s\n", err)
		os.Exit(1)
	}
	a, err := srv.Login("kyle", "hello")
	if err != nil {
		fmt.Printf("Failed to login: %s\n", err)
		os.Exit(1)
	}
	fmt.Printf("Received Actor: %s\n", a)

	err = srv.Test(a)
	if err != nil {
		fmt.Printf("Test error: %s\n", err)
	}
}
