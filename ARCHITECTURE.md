Disclaimer: This is a work in progress document for how the next generation of SharedVault will work.


# Vault

The Vault is the file that contains the secrets as well as required data to access them. This is encoded as json.

```json
{
    "secrets": {
        <title>: {
            "content": <base64 encoded binary data>,
            "min_keys": <int>,
            "scrypt_cfg": {
                "salt": <base64 encoded binary data>,
                "n": <int=16384>,
                "r": <int=8>,
                "p": <int=1>,
                "dklen": <int=32>,
            },
        }
    }
}
```

# Open questions
* Where to store the keys ? In the user or in the secret ?
* How to support the use case where the user controls his private keys ?
