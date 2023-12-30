package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/manifoldco/promptui"
	"pault.ag/go/ykpiv"
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
		Mask:  '*',
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
		Label:     "Would you like to store your wallet in another Yubikey? This can not be done later.",
		IsConfirm: true,
		Default:   "N",
	}
	result, err := prompt.Run()
	return result == "Y", err
}

func WaitForNextYubikeyPrompt() error {
	prompt := promptui.Prompt{
		Label: "Please insert next Yubikey and hit enter.",
	}
	_, err := prompt.Run()
	return err
}

func PromptPin() (string, error) {
	validate := func(input string) error {
		if len(input) < 6 {
			return fmt.Errorf("PIN must be at least 6 characters")
		}
		return nil
	}
	prompt := promptui.Prompt{
		Label:    "Yubikey PIN",
		Mask:     '*',
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
		// Create new seed and mnemonic
		seed, mnemonic, err := CreateNewSeedAndMnemonic()
		if err != nil {
			panic(err)
		}
		// Create new private key and certificate for Yubikey
		privateKey, certificate, err := CreatePrivateKeyAndCertificate(seed)
		if err != nil {
			panic(err)
		}

		var loopedOnce bool = false

		for {
			if loopedOnce {
				WaitForNextYubikeyPrompt()
			}

			// Get available Yubikey
			ykReader, err := GetYubikeyReader()
			if err != nil {
				panic(err)
			}

			// Ask for Yubikey management key
			managementKey, err := PromptManagementKey()
			if err != nil {
				continue
			}
			// Initiate Yubikey
			yubikey, err := ykpiv.New(ykpiv.Options{
				Reader:        ykReader,
				ManagementKey: managementKey,
			})
			defer yubikey.Close()

			err = yubikey.Authenticate()
			if err != nil {
				panic(err)
			}
			// Import private key and certificate to Yubikey
			_, err = yubikey.ImportKey(ykpiv.KeyManagement, privateKey)
			if err != nil {
				panic(err)
			}
			err = yubikey.SaveCertificate(ykpiv.KeyManagement, *certificate)
			if err != nil {
				panic(err)
			}

			// Store same private key and seed to another Yubikey
			storeInAnother, err := PromptStoringInAnotherKey()
			if err == nil && storeInAnother {
				loopedOnce = true
				continue
			}
			break
		}
		println("Mnemonic:", mnemonic)

	} else {
		// Get available readers
		ykReader, err := GetYubikeyReader()
		if err != nil {
			panic(err)
		}
		// Ask for PIN
		pin, err := PromptPin()
		if err != nil {
			panic(err)
		}

		// Initiate Yubikey
		yubikey, err := ykpiv.New(ykpiv.Options{
			Reader: ykReader,
			PIN:    &pin,
		})
		defer yubikey.Close()

		// Login with pin to Yubikey
		err = yubikey.Login()
		if err != nil {
			panic(err)
		}

		// Get certificate and seed from Yubikey
		cert, err := yubikey.GetCertificate(ykpiv.KeyManagement)
		if err != nil {
			panic(err)
		}
		encodedSeed, err := GetEncryptedSeedFromCertificate(cert)
		if err != nil {
			panic(err)
		}

		// Get Slot from Yubikey and decrypt seed
		slot, err := yubikey.KeyManagement()
		if err != nil {
			panic(err)
		}
		seed, err := slot.Decrypt(rand.Reader, encodedSeed, nil)
		if err != nil {
			panic(err)
		}

		// Get Master Key from seed and print address
		masterKey, err := CreateNewMasterKey(seed, *testnet)
		if err != nil {
			panic(err)
		}
		address, privateKey, err := GetAddressFromMasterKey(masterKey, 0, *testnet)
		if err != nil {
			panic(err)
		}
		println("Address:", address)
		println("Private Key:", privateKey)
	}
}
