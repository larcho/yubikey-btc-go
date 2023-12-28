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
    "os"
    "time"
)

func cert_test() {
  // Generate RSA Private Key
  priv, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    panic(err)
  }

  // Convert hex string to byte array
  payloadString := "d341750f389f668a6d14b11b89e307d207b7c2d3d1326e5ba4a92bd1a83903874d42f95f7b66e8c294509136c78e5d2dd0790d47febea25ab2c9190592973f2f"
  payload, err := hex.DecodeString(payloadString)
  if err != nil {
    panic(err)
  }

  // Encrypt hex string with RSA Public Key
  pub := priv.PublicKey
  enc, err := rsa.EncryptPKCS1v15(rand.Reader, &pub, payload)
  if err != nil {
    panic(err)
  }

  // Create Certificate base
  notBefore := time.Now()
  notAfter := notBefore.Add(365 * 24 * time.Hour)

  serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
  if err != nil {
    panic(err)
  }

  template := x509.Certificate{
    SerialNumber: serialNumber,
    Subject: pkix.Name{
      Organization: []string{"Yubikey BTC Wallet"},
    },
    NotBefore: notBefore,
    NotAfter:  notAfter,
    BasicConstraintsValid: true,
  }

  // Define custom extension
  customExt := pkix.Extension{
    Id: asn1.ObjectIdentifier{2, 25, 9999, 1},
    Critical: false,
    Value: enc,
  }

  template.ExtraExtensions = []pkix.Extension{customExt}


  // Save Private Key
  privBytes := x509.MarshalPKCS1PrivateKey(priv)
  privOut, err := os.Create("key-001.pem")
  if err != nil {
    panic(err)
  }
  pem.Encode(privOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
  privOut.Close()

  // Create Certificate
  derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
  if err != nil {
    panic(err)
  }

  // Save Certificate to file
  certOut, err := os.Create("cert-001.pem")
  if err != nil {
    panic(err)
  }
  pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
  certOut.Close()
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

