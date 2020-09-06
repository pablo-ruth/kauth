package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

func main() {

	// Parse user/group from flags
	userPtr := flag.String("user", "", "user")
	groupPtr := flag.String("group", "", "group")
	flag.Parse()

	user := *userPtr
	groups := []string{*groupPtr}

	// Load certificate authority
	caCert, caKey, err := LoadCA()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Generate user certificate
	cert, key, err := GenerateUserCertificate(user, groups, caCert, caKey)
	if err != nil {
		fmt.Printf("failed to generate user certificate: %s", err)
		return
	}

	// Write generated certificate to kubeconfig
	err = WriteCertificateToKubeconfig(user, cert, key)
	if err != nil {
		fmt.Printf("failed to write user certificate to kubeconfig: %s", err)
	}
}

// LoadCA load and parse certificate and private key of a Certificate Authority from files
func LoadCA() (*x509.Certificate, *rsa.PrivateKey, error) {

	// Read and decode private key
	keyFile, err := ioutil.ReadFile("certs/ca.key")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key: %s", err)
	}
	keyDecoded, _ := pem.Decode(keyFile)

	// Parse private key
	key, err := x509.ParsePKCS1PrivateKey(keyDecoded.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key")
	}

	// Read and decode certificate
	certFile, err := ioutil.ReadFile("certs/ca.crt")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %s", err)
	}
	certDecoded, _ := pem.Decode(certFile)

	// Parse certificate
	cert, err := x509.ParseCertificate(certDecoded.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %s", err)
	}

	return cert, key, nil
}

// GenerateUserCertificate returns a new user certificate and private key
func GenerateUserCertificate(user string, groups []string, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte, error) {

	// Generate a new user private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("failed to generate private key: %s", err)
	}

	// Create user certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   user,
			Organization: groups,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(12 * time.Hour),
	}

	// Create user certificate from template and CA
	cert, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return []byte{}, []byte{}, fmt.Errorf("failed to generate certificate: %s", err)
	}

	// PEM encodes private key and cert
	pemKey := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	pemCert := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}

	return pem.EncodeToMemory(pemCert), pem.EncodeToMemory(pemKey), nil
}

// WriteCertificateToKubeconfig writes a user certificate and private key to kubeconfig file
func WriteCertificateToKubeconfig(user string, cert, key []byte) error {

	// Open default Kubeconfig
	config, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil {
		return fmt.Errorf("failed to get kubeconfig: %s", err)
	}

	// Create/Patch user auth config with generated certificate
	auth := api.NewAuthInfo()
	auth.ClientCertificateData = cert
	auth.ClientKeyData = key
	config.AuthInfos[user] = auth

	// Write updated kubeconfig to disk
	err = clientcmd.ModifyConfig(clientcmd.NewDefaultPathOptions(), *config, true)
	if err != nil {
		return fmt.Errorf("failed to update kubeconfig on disk: %s", err)
	}

	return nil
}
