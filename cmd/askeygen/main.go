package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path"
	"time"
)

var port = 8181

func main() {
	dir, err := os.UserConfigDir()
	if err != nil {
		fmt.Printf("Could not locate authsrv config dir: %s\n", err)
	}
	d := path.Join(dir, "vlpoc-authsrv")
	var authdir = flag.String("d", d, "directory into which askeygen will place the certificates")
	flag.Parse()

	err = os.MkdirAll(*authdir, 0700)
	if err != nil {
		fmt.Printf("Failed to create authdir %s: %s\n", authdir, err)
		return
	}

	err = NewAuthSrv(*authdir, "vlpoc.com", false)
	if err != nil {
		fmt.Printf("Failed to generate keys: %s\n", err)
		return
	}
}

// NewAuthSrv creates a new instance of AuthSrv which will store
// certificates, keys, and other data in the authdir directory.
// If there is not already a certificate authority cert and key
// named ca.cert.pem and ca.key.pem in authdir, NewAuthSrv will
// create them. The ca cert should be distributed to clients so
// that they can authenticate services on the network.
func NewAuthSrv(authdir, organization string, create bool) error {
	cacertfile := path.Join(authdir, "ca.crt.pem")
	cakeyfile := path.Join(authdir, "ca.key.pem")
	certfile := path.Join(authdir, "authsrv.crt.pem")
	keyfile := path.Join(authdir, "authsrv.key.pem")

	if _, err := os.Stat(cacertfile); err == nil {
		return fmt.Errorf("%s already exists", cacertfile)

	}

	if _, err := os.Stat(certfile); err == nil {
		return fmt.Errorf("%s already exists", certfile)
	} else if _, err := os.Stat(keyfile); err == nil {
		return fmt.Errorf("%s already exists", keyfile)

	}

	err := createCA(cacertfile, cakeyfile, organization)
	if err != nil {
		return err
	}
	err = generateAuthCert(certfile, keyfile, cacertfile, cakeyfile, "auth@"+organization)
	if err != nil {
		return err
	}
	return nil
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
