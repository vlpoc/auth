package auth

import (
	"bytes"
	context "context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"fmt"
	"log"

	"github.com/vlpoc/proto/auth"
	grpc "google.golang.org/grpc"
)

func containsRSACert(protos []string) bool {
	for _, p := range protos {
		if p == RSACERT {
			return true
		}
	}
	return false
}

func PerformAuthentication(c auth.AuthClient, key *rsa.PrivateKey, a *auth.Actor) (*auth.AuthCert, error) {
	ac, err := c.Authenticate(context.Background())
	if err != nil {
		return nil, err
	}
	defer ac.CloseSend()

	m, err := ac.Recv()
	if err != nil {
		return nil, err
	}

	protos := m.GetProtos()
	if protos == nil {
		return nil, fmt.Errorf("Failed to receive challenge. Got %#v instead.", m)
	} else if !containsRSACert(protos.Protocols) {
		return nil, fmt.Errorf("Cannot authenticate with %s. Server accepts %v.", RSACERT, protos)
	}

	err = ac.Send(&auth.AuthMsg{Msg: &auth.AuthMsg_Begin{&auth.BeginAuth{Protocol: RSACERT}}})
	if err != nil {
		return nil, err
	}

	m, err = ac.Recv()
	if err != nil {
		return nil, err
	}
	start := m.GetRsaStart()
	if start == nil {
		return nil, fmt.Errorf("Failed to receive RSAStart. Got %#v instead.", m)
	}

	a.Authenticator = start.Authenticator
	var bs bytes.Buffer
	bs.WriteString(a.ActorString())
	bs.Write(start.Nonce)
	hash := sha512.Sum512(bs.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, hash[:])
	if err != nil {
		log.Printf("ERROR Failed to sign proof: %s", err)
		return nil, fmt.Errorf("Failed to sign proof: %s", err)
	}

	cnonce := make([]byte, 16)
	n, err := rand.Read(cnonce)
	if err != nil || n < 16 {
		log.Printf("ERROR Failed to create nonce: %s", err)
		return nil, fmt.Errorf("Failed to create nonce: %s", err)
	}
	err = ac.Send(&auth.AuthMsg{Msg: &auth.AuthMsg_Proof{&auth.RSAProof{Actor: a, Nonce: cnonce, Signature: sig}}})
	if err != nil {
		log.Printf("ERROR Sending RSAProof: %s", err)
		return nil, fmt.Errorf("Sending RSAProof: %s", err)
	}

	m, err = ac.Recv()
	if err != nil {
		return nil, err
	}
	cert := m.GetCert()
	if cert == nil {
		return nil, fmt.Errorf("Failed to receive AuthCert. Got %#v instead.", m)
	}

	// TODO: Validate cert
	return cert, nil
}

func AuthenticateRSA(conn string, key *rsa.PrivateKey, a *auth.Actor) (*auth.AuthCert, error) {
	c, err := grpc.Dial(conn, grpc.WithInsecure())
	if err != nil {
		//log.Printf("Failed to dial auth: %s", err)
		return nil, err
	}
	defer c.Close()
	cli := auth.NewAuthClient(c)
	cert, err := PerformAuthentication(cli, key, &auth.Actor{Name: "kyle", Domain: "users"})
	if err != nil {
		//log.Printf("Failed to authenticate: %s", err)
		return nil, err
	}
	return cert, nil
}

func Validate(a *auth.AuthCert) error {
	conn, err := grpc.Dial(a.Actor.Authenticator, grpc.WithInsecure())
	if err != nil {
		//log.Printf("Failed to dial auth: %s", err)
		return err
	}
	defer conn.Close()
	cli := auth.NewAuthClient(conn)
	_, err = cli.Validate(context.Background(), a)
	return err
}
