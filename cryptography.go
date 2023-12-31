package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func CreatePrivateKeyAndEncodeSeed(seed []byte) (
	*rsa.PrivateKey,
	*x509.Certificate,
	[]byte,
	error,
) {
	// Generate RSA Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}

	// Encode seed
	publicKey := privateKey.PublicKey
	encodedSeed, err := rsa.EncryptPKCS1v15(rand.Reader, &publicKey, seed)
	if err != nil {
		return nil, nil, nil, err
	}

	//Create Certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(25 * 365 * 24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
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

	// Create Certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, cert, encodedSeed, nil
}
