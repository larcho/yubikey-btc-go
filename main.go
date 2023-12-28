package main

func main() {
  //cert_test()
  //decrypt()
  extendedKey, _, err := CreateNewMasterKey()
  if err != nil {
    panic(err)
  }
  address, _, err := GetAddressFromMasterKey(extendedKey, 0)
  if err != nil {
    panic(err)
  }

  println("ExtendedKey", extendedKey.String())
  println("address: ", address)
}
