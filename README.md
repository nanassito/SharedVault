# SharedVault
SharedVault is a small application that allows you to define a secret that will require multiple people to unlock.

# How does it work ?
At the core, SharedVault uses Shamir's Secret Sharing algorythm (some code is directly copied from the wikipedia page). This allows us to define a key(M, N) and N parts where the key can be recovered from M parts. 
On top of that we add a layer where each user has a public/private key that encrypts the shares they hold.
This allows the following features:
* A user change chose and change their password.
* A user has a single password to remember (instead of one per share).
* We can grant users access without having to communicate the share over untrusted network.

# Security consideration
## Private keys
Private keys are store in the main database and encrypted with the user's password. A weak/leaked password will compromise the private key and therefore all the shares it can decrypt.

## Secret encryption
The secret itself is encrypted using the Fernet algorythm. The key is derived with Scrypt from the secret number generated by Shamir's Secret Sharing algorythm. 
Note that I have no idea what I am doing so it is likely that there is a flaw related to the scrypt configuration that could compromise a secret's safety.

## Revoking access
Everytime a secret is updated we generate a brand new set of keys for the new encryption. This allows us to deny future access to a user that has their key removed from the secret.

# How to use it ?

I will add more ways to use this tool but right now there is a cli that you can run with:
```
$ pipenv run python -m cli --db=$DB_CONN_STR --help
```

Depending on the type of database you use, you might need additional dependencies. You can read more about the connection string format, available backends and additional dependencies at https://docs.sqlalchemy.org/en/13/core/engines.html.