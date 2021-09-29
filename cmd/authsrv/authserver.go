package main

import (
	"bytes"
	context "context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"log"
	"time"

	"github.com/vlpoc/auth"
	authproto "github.com/vlpoc/proto/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type (
	Domain    string
	ActorName string
)

type AuthSrv struct {
	authproto.UnimplementedAuthServer
	Key     *rsa.PrivateKey
	Keys    map[Domain]map[ActorName]*rsa.PublicKey
	Address string
}

func (s *AuthSrv) rsaCert(as authproto.Auth_AuthenticateServer) error {
	anonce := make([]byte, 16)
	n, err := rand.Read(anonce)
	if err != nil || n < 16 {
		return status.Errorf(codes.Aborted, "Auth Error")
	}
	err = as.Send(&authproto.AuthMsg{Msg: &authproto.AuthMsg_RsaStart{&authproto.RSAStart{Authenticator: s.Address, Nonce: anonce}}})
	if err != nil {
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}

	m, err := as.Recv()
	if err != nil {
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}

	proof := m.GetProof()
	if proof == nil {
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}

	a := proof.Actor
	// TODO: Timing attacks
	key, err := s.keyForActor(a)
	if err != nil {
		return err
	}

	var bs bytes.Buffer
	bs.WriteString(proof.Actor.ActorString())
	bs.Write(anonce)
	hash := sha512.Sum512(bs.Bytes())
	err = rsa.VerifyPKCS1v15(key, crypto.SHA512, hash[:], proof.Signature)
	if err != nil {
		log.Printf("ERROR Verifying signature: %s", err)
		return status.Errorf(codes.Aborted, "Bad Signature")
	}

	ts := time.Now().Add(10 * time.Hour).Unix()
	bs.Reset()
	bs.WriteString(proof.Actor.ActorString())
	binary.Write(&bs, binary.LittleEndian, ts)
	bs.Write(proof.Nonce)
	bs.Write(x509.MarshalPKCS1PublicKey(key))
	hash = sha512.Sum512(bs.Bytes())
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA512, hash[:])
	if err != nil {
		log.Printf("ERROR Signing AuthCert: %s", err)
		return status.Errorf(codes.Aborted, "Bad Signature")
	}

	err = as.Send(&authproto.AuthMsg{Msg: &authproto.AuthMsg_Cert{&authproto.AuthCert{Actor: a, Expire: ts, Nonce: proof.Nonce, Pubkey: x509.MarshalPKCS1PublicKey(key), Signature: sig}}})
	if err != nil {
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	log.Printf("Successfully authenticated %s", a.ActorString())

	return nil
}

func (s *AuthSrv) Authenticate(as authproto.Auth_AuthenticateServer) error {
	err := as.Send(&authproto.AuthMsg{Msg: &authproto.AuthMsg_Protos{Protos: &authproto.Protocols{Protocols: []string{auth.RSACERT}}}})
	if err != nil {
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	m, err := as.Recv()
	if err != nil {
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	begin := m.GetBegin()
	if begin == nil {
		return status.Errorf(codes.Aborted, "Bad Auth RPC")
	}
	switch begin.Protocol {
	case auth.RSACERT:
		return s.rsaCert(as)
	default:
		return status.Errorf(codes.Aborted, "Invalid Auth Method")
	}
}

func (s *AuthSrv) keyForActor(a *authproto.Actor) (*rsa.PublicKey, error) {
	names, ok := s.Keys[Domain(a.Domain)]
	if !ok {
		log.Printf("ERROR No such domain: %s", a.Domain)
		return nil, status.Errorf(codes.Aborted, "Bad Signature")
	}
	key, ok := names[ActorName(a.Name)]
	if !ok {
		log.Printf("ERROR No such key: %s/%s", a.Domain, a.Name)
		return nil, status.Errorf(codes.Aborted, "Bad Signature")
	}
	// 	nk, err := rsa.GenerateKey(rand.Reader, 4096)
	// 	if err == nil {
	// 		names[ActorName(a.Name)] = nk.Public().(*rsa.PublicKey)
	// 	}
	return key, nil
}

func (s *AuthSrv) Validate(ctx context.Context, in *authproto.AuthCert) (*authproto.Empty, error) {
	var bs bytes.Buffer
	bs.WriteString(in.Actor.ActorString())
	binary.Write(&bs, binary.LittleEndian, in.Expire)
	bs.Write(in.Nonce)
	bs.Write(in.Pubkey)
	hash := sha512.Sum512(bs.Bytes())
	err := rsa.VerifyPKCS1v15(s.Key.Public().(*rsa.PublicKey), crypto.SHA512, hash[:], in.Signature)
	if err != nil {
		log.Printf("ERROR Validating AuthCert: %s", err)
		return nil, status.Errorf(codes.Aborted, "Invalid Cert")
	}
	key, err := x509.ParsePKCS1PublicKey(in.Pubkey)
	if err != nil {
		log.Printf("ERROR Validating AuthCert: Couldn't parse public key: %s", err)
		return nil, status.Errorf(codes.Aborted, "Invalid Cert")
	}

	sKey, err := s.keyForActor(in.Actor)
	if err != nil {
		log.Printf("ERROR Failed to retreive key for actor %s: %s", in.Actor.ActorString(), err)
		return nil, status.Errorf(codes.Aborted, "Invalid Cert")
	}
	if !sKey.Equal(key) {
		log.Printf("ERROR Public Key for %s from AuthCert has expired.", in.Actor.ActorString())
		return nil, status.Errorf(codes.Aborted, "Invalid Cert")
	}

	if certTime := time.Unix(in.Expire, 0); certTime.Before(time.Now()) {
		log.Printf("ERROR Certificate expired %s ago.", time.Now().Sub(certTime))
		return nil, status.Errorf(codes.Aborted, "Invalid Cert")
	}

	return &authproto.Empty{}, nil
}
