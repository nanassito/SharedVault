Disclaimer: This is a work in progress document for how the next generation of SharedVault will work.


# Vault

The Vault is the file that contains the secrets as well as required data to access them. This is encoded as json.

```jsonc
{
    "secrets": {
        "...": {  // Title of the secret, this information is public
            "content": "...",  // base64 encoded binary data,
            "min_keys":  // int,
            "scrypt_cfg": {
                "salt":  // base64 encoded binary data,
                "n":  // int=16384,
                "r":  // int=8,
                "p":  // int=1,
                "dklen":  // int=32,
            },
            "keys": [
                // The position in this array denotes the position of the key where `position = idx + 1`
                {
                    // KV pairs, the key is the username of the user owning the private key.
                    // The value is the RSA encrypted value of the key.
                    "...": "...",
                },
            ],
        }
    },
    "users": {
        // Every user must have an entry here, even if they manage their own keys.
        "...": {  // Username
            // Since we use Gpg, the private key can be embedded in here or it can be a shim pointing to a key card.
            "gpg_public_pem": "...",
            "gpg_private_pem": "...",
        }
    }
}
```

# Open questions
