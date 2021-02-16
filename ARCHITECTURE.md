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
            "type": "...",
            "public_key_pem_bytes": "...",  // Base64 representation of the PEM serialization of the RSA public key of this user.
            // There may be additional fields depending on the user type. See The dedicated section for more details.
        }
    }
}
```

# User types
We anticipate a couple of types of users.

### Password
This user has their private key stored in the vauld but encrypted with a password. While not the most secure option, it is likely the most user friendly.

```jsonc
{
    "type": "password",
    "public_key_pem_bytes": "...",
    "private_key_pem_bytes": "...",  // Base 64 encoding of the PEM/PKCS8 serialization of the RSA private key of this user.
}
```

### External
This user controls their own private key as they please. This means they will have to manually sign messages in order to use SharedVault.
```jsonc
{
    "type": "password",
    "public_key_pem_bytes": "...",
}
```

### Yubikey
This user has their private key stored on a yubikey.
// TODO: Figure out how we can use this directly.


# Open questions
