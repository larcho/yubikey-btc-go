package main

import (
  "fmt"
  "flag"
  "crypto/rand"
  "pault.ag/go/ykpiv"
  "github.com/manifoldco/promptui"
  "encoding/hex"
)

func GetYubikeyReader() (string, error) {
    readers, err := ykpiv.Readers()
    if err != nil {
      return "", err
    }
    if len(readers) <= 0 {
      return "", fmt.Errorf("No Yubikey found.")
    }
    if len(readers) > 1 {
      return "", fmt.Errorf("Multiple Yubikeys found.")
    }
    return readers[0], nil
}

func PromptManagementKey() ([]byte, error) {
  const defaultManagementKey = "010203040506070801020304050607080102030405060708"

  prompt := promptui.Prompt{
    Label: "Yubikey Management Key (Leave blank for default)",
    Mask: '*',
  }

  result, err := prompt.Run()
  if err != nil {
    return nil, err
  }
  if len(result) <= 0 {
    return hex.DecodeString(defaultManagementKey)
  } else {
    return hex.DecodeString(result)
  }
}

func PromptStoringInAnotherKey() (bool, error) {
  prompt := promptui.Prompt{
		Label:     "Would you like to store your wallet in another Yubikey?",
		IsConfirm: true,
    Default: "N",
	}
  result, err := prompt.Run()
  return result == "Y", err
}

func PromptPin() (string, error) {
  validate := func(input string) error {
    if len(input) < 6 {
      return fmt.Errorf("PIN must be at least 6 characters")
    }
    return nil
  }
  prompt := promptui.Prompt{
    Label: "Yubikey PIN",
    Mask: '*',
    Validate: validate,
  }

  return prompt.Run()
}

func main() {
  testnet := flag.Bool("testnet", false, "Enable testnet mode.")
  createnew := flag.Bool("createnew", false, "Create a new wallet.")
  flag.Parse()

  // Create new wallet and store to Yubikey
  if *createnew {
    seed, mnemonic, err := CreateNewSeedAndMnemonic()
    if err != nil {
      panic(err)
    }
    privateKey, certificate, err := CreatePrivateKeyAndCertificate(seed)
    if err != nil {
      panic(err)
    }

    for {
      ykReader, err := GetYubikeyReader()

      if err != nil {
        panic(err)
      }
      managementKey, err := PromptManagementKey()
      if err != nil {
        continue
      }

      yubikey, err := ykpiv.New(ykpiv.Options{
        Reader: ykReader,
        ManagementKey: managementKey,
      })
      defer yubikey.Close()

      err = yubikey.Authenticate()
      if err != nil {
        panic(err)
      }
      _, err = yubikey.ImportKey(ykpiv.KeyManagement, privateKey)
      if err != nil {
        panic(err)
      }
      err = yubikey.SaveCertificate(ykpiv.KeyManagement, *certificate)
      if err != nil {
        panic(err)
      }
      storeInAnother, err := PromptStoringInAnotherKey()
      if err == nil && storeInAnother {
        continue
      }
      break
    }
    println("Mnemonic:", mnemonic)

  } else {
      ykReader, err := GetYubikeyReader()
      if err != nil {
        panic(err)
      }
      pin, err := PromptPin()
      if err != nil {
        panic(err)
      }

      yubikey, err := ykpiv.New(ykpiv.Options{
        Reader: ykReader,
        PIN: &pin,
      })
      defer yubikey.Close()

      err = yubikey.Login()
      if err != nil {
        panic(err)
      }

      cert, err := yubikey.GetCertificate(ykpiv.KeyManagement)
      if err != nil {
        panic(err)
      }
      encodedSeed, err := GetEncryptedSeedFromCertificate(cert)
      if err != nil {
        panic(err)
      }
      slot, err := yubikey.KeyManagement()
      if err != nil {
        panic(err)
      }
      seed, err := slot.Decrypt(rand.Reader, encodedSeed, nil)
      if err != nil {
        panic(err)
      }

      masterKey, err := CreateNewMasterKey(seed, *testnet)
      if err != nil {
        panic(err)
      }
      address, _, err := GetAddressFromMasterKey(masterKey, 0, *testnet)
      if err != nil {
        panic(err)
      }
      println("Address:", address)
  }
}
