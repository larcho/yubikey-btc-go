package main

import (
  "flag"
)

func main() {
  testnet := flag.Bool("testnet", false, "Use testnet.")
  flag.Parse()

  //cert_test()
  //decrypt()
  seed, mnemonic, err := CreateNewSeedAndMnemonic()
  if err != nil {
    panic(err)
  }
  extendedKey, err := CreateNewMasterKey(seed, *testnet)
  if err != nil {
    panic(err)
  }
  address, _, err := GetAddressFromMasterKey(extendedKey, 0, *testnet)
  if err != nil {
    panic(err)
  }

  println("Mnemonic:", mnemonic)
  println("address:", address)
}
