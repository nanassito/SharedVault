# Usage behavior

```py
from sharedvault import SharedVault
from sharedvault.users import PasswordUser


with SharedVault("path/to/vault.svlt") as vault:
    vault.users  # Dict of username to User
    vault.users["dorian"] = PasswordUser(password=b"drowssap")
    
    example_user = list(vault.users.values())[0]
    example_user.public_key  # RSA public key
    example_user.type  # User type as defined in ARCHITECTURE.md
    
    vault.secrets  # Dict of secret title to Secret
    # Create a new secret
    vault.secrets["something new"] = Secret(
        content="this sentence is secret", 
        min_keys=2,
        keys=[
            {"dorian"},
            {"aline", "zaya"},
            {"zaya"},
        ],
    )
    
    example_secret = list(vault.users.values())[0]
    example_secret.min_keys  # Minimum number of keys needed to open the secret
    example_secret.keys  # List of key-value pairs where the key is a user name and the value is the key encrypted with that user's public key.
    
    with vault.users["dorian"].authenticate() as authed_user:
        authed_user.grant("zaya", 0, "something new")  # Give permission to zaya to use key number 0
        
        with authed_user.open("something_new") as secret:
            secret.min_keys = 3
            secret.content = "This updated sented is secret"
```

