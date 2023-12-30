# Yubikey BTC Cold Wallet

This wallet aims to store itself completely within a Yubikey leveraging the available PIV feature. It accomplishes this by storing a BIP32 seed encrypted in a certificate at the “Key Management” slot. The app is able to generate a BIP 39 Mnemonic seed, generate replicable RSA2048 pairs during setup so the wallet can be backed up into multiple Yubikeys and generate BIP84 addresses at any given index.

Since this is a cold wallet, doing Bitcoin transactions isn’t currently available. If you want to generate a transfer you do have multiple options:

- Print the private key for the corresponding BIP84 address. This can be imported into a hot wallet.
- Import the entire wallet using the mnemonic words. 

## This app uses the following Go dependencies
- [btcd](https://github.com/btcsuite/btcd)
- [go-ykpiv](https://github.com/go-piv/go-ykpiv)
