Disclaimer: This is a work in progress document for how the next generation of SharedVault will work.


# Vault

The Vault is the file that contains the secrets as well as required data to access them. This is encoded as json.

```jsonc
{
    "secrets": {
        "...": {  // Name/ID of the secret
            "aes_nonce": base64,  // Nonce used by the AES cipher
            "aes_tag": base64,  // Tag/digest of the content encryption
            "content": base64, // AES encrypted content
            "keys": [
                // The position in the array is the position in the shamir algorithm (idx + 1 = position)
                "-----BEGIN PGP MESSAGE-----\n..."  // PGP encrypted Shamir shares
                // To grant a key to multiple people, the message is encrypted with multiple public keys.
            ],
            "min_keys": int
        }
    },
    "users": [
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n..."  // Public AND private PGP key.
        // The assumptions are:
        // * Keys contain exactly one uid.
        // * uids[0].name is unique in a sharedvault file.
    ]
}
```
