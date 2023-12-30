package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

func CreatePrivateKeyAndCertificate(seed []byte) (*rsa.PrivateKey, *x509.Certificate, error) {
	// Generate RSA Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Encode seed
	publicKey := privateKey.PublicKey
	encodedSeed, err := rsa.EncryptPKCS1v15(rand.Reader, &publicKey, seed)
	if err != nil {
		return nil, nil, err
	}

	//Create Certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(25 * 365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Yubikey BTC Wallet",
			Organization: []string{"Larcho"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// Define custom extension
	customExt := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 999},
		Critical: true,
		Value:    encodedSeed,
	}
	template.ExtraExtensions = []pkix.Extension{customExt}

	// Create Certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, cert, nil
}

func GetEncryptedSeedFromCertificate(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.3.6.1.4.1.41482.999" {
			return ext.Value, nil
		}
	}
	return nil, fmt.Errorf("Seed not found.")
}
