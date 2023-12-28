package main

import (
  "github.com/btcsuite/btcd/btcutil"
  "github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

func CreateNewMasterKey() (*hdkeychain.ExtendedKey, []byte, error) {
  seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
  if err != nil {
    return nil, nil, err
  }
  masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
  if err != nil {
    return nil, nil, err
  }
  return masterKey, seed, nil
}

// Return BIP84 address
func GetAddressFromMasterKey(masterKey *hdkeychain.ExtendedKey, index uint32) (string, []byte, error) {

  var childKey *hdkeychain.ExtendedKey = masterKey
  for i := 0; i < 5; i++ {
    var derivedIndex uint32 = 0
    if i == 0 {
      derivedIndex = hdkeychain.HardenedKeyStart + 84
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

  address, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(privKey.PubKey().SerializeCompressed()), &chaincfg.MainNetParams)
  if err != nil {
    return "", nil, err
  }
  return address.EncodeAddress(), privKey.Serialize(), nil
}
