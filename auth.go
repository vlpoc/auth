package auth

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"regexp"

	"github.com/vlpoc/proto/authpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type AuthSrv struct {
	connStr string
	root    *x509.CertPool
	conn    *grpc.ClientConn
	c       authpb.AuthClient
}

func NewAuthSrv(conn string, certFile string) (*AuthSrv, error) {
	pool := x509.NewCertPool()
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("Failed to parse CA certificate.")
	}
	return &AuthSrv{connStr: conn, root: pool}, nil
}

func (s *AuthSrv) connect() error {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		RootCAs: s.root,
		VerifyConnection: func(s tls.ConnectionState) error {
			return nil
		},
		ServerName: "auth@vlpoc.com",
	}
	conn, err := grpc.Dial(s.connStr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return err
	}
	s.conn = conn
	s.c = authpb.NewAuthClient(conn)
	return nil
}

func (s *AuthSrv) Login(actor, pass string) (*Actor, error) {
	if s.c == nil {
		if err := s.connect(); err != nil {
			return nil, err
		}
	}
	sc, err := s.c.Login(context.Background())
	if err != nil {
		return nil, fmt.Errorf("Auth Error, failed to begin Login RPC: %s", err)
	}
	defer sc.CloseSend()

	m, err := sc.Recv()
	if err != nil {
		return nil, fmt.Errorf("Auth Error, while receiving challenge: %s", err)
	}
	if m.Msgtype != authpb.AuthMsg_CHALLENGE {
		return nil, fmt.Errorf("Auth Error, while receiving challenge: expected CHALLENGE, but received %s", m.Msgtype.String())
	}
	// 	// TODO: Add client nonce to prevent server-side salt poisoning
	// 	pwhash, err := dk, err := scrypt.Key([]byte(pass), m.Msg, 32768, 8, 1, 32)  //bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Auth Error, failed hashing password: %s", err)
	// 	}
	// 	fmt.Printf("Hash [%s] -> %s\n", pass, string(pwhash))
	// 	nonceHash := append(m.Msg, pwhash...)
	// 	response, err := bcrypt.GenerateFromPassword(nonceHash, bcrypt.DefaultCost)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Auth Error, failed hashing password: %s", err)
	// 	}
	// 	fmt.Printf("Hash [%s] -> %s\n", string(nonceHash), string(response))
	// TODO: Fix login security. Don't send raw password.
	err = sc.Send(&authpb.AuthMsg{Msgtype: authpb.AuthMsg_RESPONSE, Msg: []byte(pass), Actor: &actor})
	if err != nil {
		return nil, fmt.Errorf("Auth Error, while sending challenge response: %s", err)
	}
	m, err = sc.Recv()
	if err != nil {
		return nil, fmt.Errorf("Auth Error, while receiving certificate: %s", err)
	}
	if m.Msgtype != authpb.AuthMsg_CERT {
		return nil, fmt.Errorf("Auth Error, while receiving challenge: expected CERT, but received %s", m.Msgtype.String())
	}
	certBlock, rest := pem.Decode(m.Msg)
	keyBlock, _ := pem.Decode(rest)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("Failed to decode certificate from authsrv: %v", certBlock)
	}
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("Failed to decode certificate from authsrv: %v", certBlock)
	}
	if m.Actor == nil {
		return nil, fmt.Errorf("Did not receive an actor string from authsrv.")
	}
	a, err := ParseActor(*m.Actor)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse actor string \"%s\" from authsrv: %s", *m.Actor, err)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode certificate from authsrv: %s", err)
	}
	a.cert = cert

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode certificate from authsrv: %s", err)
	}
	pk, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Expected an RSA private key, but got: %v", reflect.TypeOf(key))
	}
	a.privKey = pk

	tlsCert, err := tls.X509KeyPair(m.Msg, rest)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode tls key pair: %s", err)
	}
	a.tlsCert = tlsCert
	a.srv = s
	return a, nil
}

func (s *AuthSrv) Test(a *Actor) error {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		ClientAuth:       tls.RequireAndVerifyClientCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		RootCAs:      s.root,
		ClientCAs:    s.root,
		Certificates: []tls.Certificate{a.tlsCert},
		ServerName:   "auth@vlpoc.com",
	}
	conn, err := grpc.Dial(s.connStr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return err
	}
	defer conn.Close()
	c := authpb.NewAuthClient(conn)
	_, err = c.Test(context.Background(), &authpb.Empty{})
	// 	if s.c == nil {
	// 		if err := s.connect(); err != nil {
	// 			log.Printf("FAILED TO CONNECT.")
	// 			return err
	// 		}
	// 	}
	// 	_, err := s.c.Test(context.Background(), &authpb.Empty{})
	return err
}

func (s *AuthSrv) Close() error {
	if s.conn != nil {
		s.conn.Close()
	}
	s.conn = nil
	s.c = nil
	return nil
}

type Actor struct {
	Name      string
	Namespace string
	Domain    string
	privKey   *rsa.PrivateKey
	cert      *x509.Certificate
	tlsCert   tls.Certificate
	srv       *AuthSrv
}

var actorRE *regexp.Regexp = regexp.MustCompile(`^([^/@\s]+)(/([^/@\s]+))?(@(\S+))?$`)

func ParseActor(actor string) (*Actor, error) {
	matches := actorRE.FindStringSubmatch(actor)
	if matches == nil {
		return nil, fmt.Errorf("Invalid actor string")
	}
	return &Actor{
		Name:      matches[1],
		Namespace: matches[3],
		Domain:    matches[5],
	}, nil
}

func (a *Actor) String() string {
	if a.Domain != "" {
		if a.Namespace != "" {
			return fmt.Sprintf("%s/%s@%s", a.Name, a.Namespace, a.Domain)
		} else {
			return fmt.Sprintf("%s@%s", a.Name, a.Domain)
		}
	} else {
		if a.Namespace != "" {
			return fmt.Sprintf("%s/%s", a.Name, a.Namespace)
		} else {
			return fmt.Sprintf("%s", a.Name)
		}
	}
}

func (a *Actor) Authenticated() bool {
	return false
}

func (a *Actor) Login(srv *AuthSrv) error {
	return nil
}
