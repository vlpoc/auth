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
)

// func PerformAuthentication(c AuthClient, key *rsa.PrivateKey, a *Actor) (*AuthCert, error) {
// 	ac, err := c.Authenticate(context.Background())
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer ac.CloseSend()
//
// 	bs := make([]byte, 16)
// 	n, err := rand.Read(bs)
// 	if err != nil || n < 16 {
// 		return nil, fmt.Errorf("Failed to generate challenge. Only received %d/16 bytes from cryptographic RNG", n)
// 	}
//
// 	err = ac.Send(&AuthMsg{Msg: &AuthMsg_Req{&AuthRequest{Actor: a, Method: "RSA4096"}}})
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	m, err := ac.Recv()
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	chal := m.GetChal()
// 	if chal == nil {
// 		return nil, fmt.Errorf("Failed to receive challenge. Got %#v instead.", m)
// 	}
//
// 	hash := sha512.Sum512(chal.Challenge)
// 	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA512, hash[:])
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	err = ac.Send(&AuthMsg{Msg: &AuthMsg_Chal{&Challenge{Challenge: sig}}})
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	m, err = ac.Recv()
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	cert := m.GetCert()
// 	if cert == nil {
// 		return nil, fmt.Errorf("Failed to receive cert. Got %#v instead.", m)
// 	}
// 	return cert, nil
// }

func containsRSACert(protos []string) bool {
	for _, p := range protos {
		if p == RSACERT {
			return true
		}
	}
	return false
}

func PerformAuthentication(c AuthClient, key *rsa.PrivateKey, a *Actor) (*AuthCert, error) {
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

	err = ac.Send(&AuthMsg{Msg: &AuthMsg_Begin{&BeginAuth{Protocol: RSACERT}}})
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
	err = ac.Send(&AuthMsg{Msg: &AuthMsg_Proof{&RSAProof{Actor: a, Nonce: cnonce, Signature: sig}}})
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
