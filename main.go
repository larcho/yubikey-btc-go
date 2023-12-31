package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"pault.ag/go/ykpiv"
)

const ENCODED_SEED_SLOT int32 = 0x005F0343

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
		privateKey, certificate, encodedSeed, err := CreatePrivateKeyAndEncodeSeed(seed)
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
			// Import private key, certificate and save encoed seed to Yubikey
			_, err = yubikey.ImportKey(ykpiv.KeyManagement, privateKey)
			if err != nil {
				panic(err)
			}
			err = yubikey.SaveCertificate(ykpiv.KeyManagement, *certificate)
			if err != nil {
				panic(err)
			}
			err = yubikey.SaveObject(ENCODED_SEED_SLOT, encodedSeed)
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

		// Get encoded seed from Yubikey
		encodedSeed, err := yubikey.GetObject((int)(ENCODED_SEED_SLOT))
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
		masterKey, err := GetMasterKeyFromSeed(seed, *testnet)
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
