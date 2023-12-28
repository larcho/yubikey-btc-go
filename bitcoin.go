package main

import (
  "github.com/btcsuite/btcd/btcutil"
  "github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
  "github.com/tyler-smith/go-bip39"
)

func CreateNewSeedAndMnemonic() ([]byte, string, error) {
  entropy, err := bip39.NewEntropy(256)
  if err != nil {
    return nil, "", err
  }
  mnemonic, err := bip39.NewMnemonic(entropy)
  if err != nil {
    return nil, "", err
  }
  seed := bip39.NewSeed(mnemonic, "")
  return seed, mnemonic, nil
}

func CreateNewMasterKey(seed []byte, testnet bool) (*hdkeychain.ExtendedKey, error) {
  var params *chaincfg.Params
  if testnet {
    params = &chaincfg.TestNet3Params
  } else {
    params = &chaincfg.MainNetParams
  }
  masterKey, err := hdkeychain.NewMaster(seed, params)
  if err != nil {
    return nil, err
  }
  return masterKey, nil
}

// Return BIP84 address
func GetAddressFromMasterKey(masterKey *hdkeychain.ExtendedKey, index uint32, testnet bool) (string, []byte, error) {
  var params *chaincfg.Params
  if testnet {
    params = &chaincfg.TestNet3Params
  } else {
    params = &chaincfg.MainNetParams
  }

  var childKey *hdkeychain.ExtendedKey = masterKey
  for i := 0; i < 5; i++ {
    var derivedIndex uint32 = 0
    if i == 0 {
      derivedIndex = hdkeychain.HardenedKeyStart + 84
    } else if i == 1 && testnet {
      derivedIndex = hdkeychain.HardenedKeyStart + 1
    } else if i < 3 {
      derivedIndex = hdkeychain.HardenedKeyStart + 0
    } else if i == 4 {
      derivedIndex = index
    }
    var err error
    childKey, err = childKey.Derive(derivedIndex)
    if err != nil {
      return "", nil, err
    }
  }

  privKey, err := childKey.ECPrivKey()
  if err != nil {
    return "", nil, err
  }

  address, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(privKey.PubKey().SerializeCompressed()), params)
  if err != nil {
    return "", nil, err
  }
  return address.EncodeAddress(), privKey.Serialize(), nil
}
