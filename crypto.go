package main

import (
    "crypto/rand"
    "crypto/rsa"
    "encoding/hex"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "encoding/pem"
    "io/ioutil"
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
      CommonName: "Yubikey BTC Wallet",
      Organization: []string{"Larcho"},
    },
    NotBefore: notBefore,
    NotAfter:  notAfter,
    KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
    BasicConstraintsValid: true,
  }

  // Define custom extension
  customExt := pkix.Extension{
    Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 999},
    Critical: true,
    Value: encodedSeed,
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

func loadPrivateKey(pemFile string) (*rsa.PrivateKey, error) {
    // Read the PEM file
    data, err := ioutil.ReadFile(pemFile)
    if err != nil {
        return nil, err
    }

    // Decode the PEM block
    block, _ := pem.Decode(data)
    if block == nil {
        return nil, err
    }

    // Parse the private key
    privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return privateKey, nil
}

func decrypt() {
  // Load Private Key
  priv, err := loadPrivateKey("key-001.pem")
  if err != nil {
    panic(err)
  }

  // Load certificate
  certFile, err := ioutil.ReadFile("cert-001.pem")
  if err != nil {
    panic(err)
  }

  block, _ := pem.Decode(certFile)
  if block == nil || block.Type != "CERTIFICATE" {
    panic("failed to decode PEM block containing certificate")
  }

  cert, err := x509.ParseCertificate(block.Bytes)
  if err != nil {
    panic(err)
  }

  // Get custom extension
  for _, ext := range cert.Extensions {
    if ext.Id.String() == "2.25.9999.1" {
      // Decrypt with Private Key
      dec, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ext.Value)
      if err != nil {
        panic(err)
      }

      // Convert byte array to hex string
      hexString := hex.EncodeToString(dec)
      println(hexString)
    }
  }
}

