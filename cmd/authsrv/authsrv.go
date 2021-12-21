package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path"
	"time"

	"github.com/vlpoc/proto/authpb"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type AuthSrv struct {
	authpb.UnimplementedAuthServer
	pool        *x509.CertPool
	authsrvCert tls.Certificate
	Org         string
	AuthDir     string
	hashes      map[string][]byte
}

// NewAuthSrv creates a new instance of AuthSrv which will store
// certificates, keys, and other data in the authdir directory.
// If there is not already a certificate authority cert and key
// named ca.cert.pem and ca.key.pem in authdir, NewAuthSrv will
// create them. The ca cert should be distributed to clients so
// that they can authenticate services on the network.
func NewAuthSrv(authdir, organization string) (*AuthSrv, error) {
	cacertfile := path.Join(authdir, "ca.crt.pem")
	cakeyfile := path.Join(authdir, "ca.key.pem")
	certfile := path.Join(authdir, "authsrv.crt.pem")
	keyfile := path.Join(authdir, "authsrv.key.pem")
	if _, err := os.Stat(cacertfile); os.IsNotExist(err) {
		log.Printf("Could not find %s. Creating.", cacertfile)
		err := createCA(cacertfile, cakeyfile, organization)
		if err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(certfile); os.IsNotExist(err) {
		log.Printf("Could not find %s. Creating.", certfile)
		err := generateAuthCert(certfile, keyfile, cacertfile, cakeyfile, "auth@"+organization)
		if err != nil {
			return nil, err
		}
	} else if _, err := os.Stat(keyfile); os.IsNotExist(err) {
		log.Printf("Could not find %s. Creating %s and %s", keyfile, certfile, keyfile)
		err := generateAuthCert(certfile, keyfile, cacertfile, cakeyfile, "auth@"+organization)
		if err != nil {
			return nil, err
		}
	}
	// 	cert, err := parseCertificate(certfile)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	key, err := parsePrivateKey(keyfile)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	authsrvCert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	data, err := os.ReadFile(cacertfile)
	if err != nil {
		log.Fatal("Failed to load certificate authority: %s", err)
	}
	pool.AppendCertsFromPEM(data)
	return &AuthSrv{
		pool:        pool,
		authsrvCert: authsrvCert,
		Org:         organization,
		AuthDir:     authdir,
		hashes:      make(map[string][]byte),
	}, nil
}

func (s *AuthSrv) Login(ls authpb.Auth_LoginServer) error {
	snonce := make([]byte, 16)
	n, err := rand.Read(snonce)
	if err != nil || n < 16 {
		log.Printf("Failed to generate nonce: %s", err)
		return status.Errorf(codes.Aborted, "Auth Error")
	}
	err = ls.Send(&authpb.AuthMsg{Msgtype: authpb.AuthMsg_CHALLENGE, Msg: snonce})
	if err != nil {
		log.Printf("Failed to send challenge: %s", err)
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}

	m, err := ls.Recv()
	if err != nil {
		log.Printf("Failed to receive response: %s", err)
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	if m.Msgtype != authpb.AuthMsg_RESPONSE {
		log.Printf("Expected response, but got: %s", m.Msgtype.String())
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	if m.Actor == nil || *m.Actor == "" {
		log.Printf("Responce actor is blank.")
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	pwhash, ok := s.hashes[*m.Actor]
	if !ok {
		log.Printf("No such actor %s", m.Actor)
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	// TODO: Fix password hashing
	// 	nonceHash := append(snonce, pwhash...)
	// 	err = bcrypt.CompareHashAndPassword(m.Msg, nonceHash)
	// 	if err != nil {
	// 		fmt.Printf("Hash [%s] !-> %s\n", string(nonceHash), string(m.Msg))
	// 		log.Printf("Hashed password doesn't match: %s", err)
	// 		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	// 	}
	// 	fmt.Printf("Hash [%s] -> %s\n", string(nonceHash), string(m.Msg))
	err = bcrypt.CompareHashAndPassword(pwhash, m.Msg)
	if err != nil {
		log.Printf("Hashed password doesn't match: %s", err)
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}

	// Client successfully authenticated.
	actorName := *m.Actor + "@" + s.Org
	bs, err := s.generateCert(actorName)
	if err != nil {
		log.Printf("Failed to generate certificate for client: %s", err)
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	err = ls.Send(&authpb.AuthMsg{Msgtype: authpb.AuthMsg_CERT, Msg: bs, Actor: &actorName})
	if err != nil {
		log.Printf("Failed to send certificate to client: %s", err)
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	return nil
}

func (s *AuthSrv) Test(ctx context.Context, _ *authpb.Empty) (*authpb.Empty, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("NO PEER")
	}
	log.Printf("PEER: %#v\n", peer)
	log.Printf("AuthInfo: %#v\n", peer.AuthInfo)
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("NO TLSInfo")
	}
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, fmt.Errorf("NO Verified chains.")
	}
	v := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName
	log.Printf("%v - %v\n", peer.Addr.String(), v)
	return &authpb.Empty{}, nil
}

func generateAuthCert(certfile, keyfile, cacertfile, cakeyfile, actor string) error {
	cacert, err := parseCertificate(cacertfile)
	if err != nil {
		return err
	}
	cakey, err := parsePrivateKey(cakeyfile)
	if err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("ERROR Generating Private key: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("Failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"VLPOC"},
			CommonName:   actor,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * time.Hour), // 10 hours

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			actor,
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, cacert, &key.PublicKey, cakey)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}

	certF, err := os.Create(certfile)
	if err != nil {
		return fmt.Errorf("Failed to create %s: %s", certfile, err)
	}
	defer certF.Close()
	if err := pem.Encode(certF, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fmt.Errorf("Failed to encode certificate PEM: %s", err)
	}

	keyF, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("Failed to create %s: %s", keyfile, err)
	}
	defer keyF.Close()
	keybs, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("Failed to encode private key: %s", err)
	}
	if err := pem.Encode(keyF, &pem.Block{Type: "PRIVATE KEY", Bytes: keybs}); err != nil {
		return fmt.Errorf("Failed to encode private key PEM: %s", err)
	}
	return nil
}

// generateCert generates a certificate and private key for the actor described by actorString.
// This is returned as a PEM-encoded string containing first the cert, followed by the private key.
func (s *AuthSrv) generateCert(actorString string) ([]byte, error) {
	cacertfile := path.Join(s.AuthDir, "ca.crt.pem")
	cakeyfile := path.Join(s.AuthDir, "ca.key.pem")
	cacert, err := parseCertificate(cacertfile)
	if err != nil {
		return nil, err
	}
	cakey, err := parsePrivateKey(cakeyfile)
	if err != nil {
		return nil, err
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("ERROR Generating Private key: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{s.Org},
			CommonName:   actorString,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * time.Hour), // 10 hours

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			actorString,
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, cacert, &key.PublicKey, cakey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create certificate: %s", err)
	}
	var bs bytes.Buffer
	if err := pem.Encode(&bs, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return nil, fmt.Errorf("Failed to encode certificate PEM: %s", err)
	}
	keybs, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Failed to encode private key: %s", err)
	}
	if err := pem.Encode(&bs, &pem.Block{Type: "PRIVATE KEY", Bytes: keybs}); err != nil {
		return nil, fmt.Errorf("Failed to encode private key PEM: %s", err)
	}
	return bs.Bytes(), nil
}

func (s *AuthSrv) credentials() credentials.TransportCredentials {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.VerifyClientCertIfGiven,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		RootCAs:      s.pool,
		ClientCAs:    s.pool,
		Certificates: []tls.Certificate{s.authsrvCert},
		VerifyConnection: func(s tls.ConnectionState) error {
			return nil
		},
	}
	return credentials.NewTLS(cfg)
}

func createCA(certfile, keyfile, organization string) error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("ERROR Generating Server CA key: %s", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("Failed to generate serial number: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{organization},
			CommonName:   "Certificate Authority",
		},
		IsCA:      true,
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		//DNSNames: []string{
		//	"*.vlpoc.com",
		//	"ca@vlpoc.com",
		//},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}

	certF, err := os.Create(certfile)
	if err != nil {
		return fmt.Errorf("Failed to create %s: %s", certfile, err)
	}
	defer certF.Close()
	if err := pem.Encode(certF, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fmt.Errorf("Failed to encode certificate PEM: %s", err)
	}

	keyF, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("Failed to create %s: %s", keyfile, err)
	}
	defer keyF.Close()
	keybs, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("Failed to encode private key: %s", err)
	}
	if err := pem.Encode(keyF, &pem.Block{Type: "PRIVATE KEY", Bytes: keybs}); err != nil {
		return fmt.Errorf("Failed to encode private key PEM: %s", err)
	}
	return nil
}

func parseCertificate(certfile string) (*x509.Certificate, error) {
	pembs, err := os.ReadFile(certfile)
	if err != nil {
		return nil, fmt.Errorf("Failed to open %s: %s", certfile, err)
	}
	block, _ := pem.Decode(pembs)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode PEM for %s: No PEM block found", certfile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse certificate in %s: %s", certfile, err)
	}
	return cert, nil
}

func parsePrivateKey(keyfile string) (*rsa.PrivateKey, error) {
	pembs, err := os.ReadFile(keyfile)
	if err != nil {
		return nil, fmt.Errorf("Failed to open %s: %s", keyfile, err)
	}
	block, _ := pem.Decode(pembs)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode PEM for %s: No PEM block found", keyfile)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode private key: %s", err)
	}
	return key.(*rsa.PrivateKey), nil
}
