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
Private keys are stored in the main database and encrypted with the user's password. A weak/leaked password will compromise the private key and therefore all the shares it can decrypt.

## Revoking access
Everytime a secret is updated we generate a brand new set of keys for the new encryption. This allows us to deny future access to a user that has their key removed from the secret.

## Deletion
SharedVault uses the file you provide as a storage, therefore it is impossible for us to protect against deletion since the file itself could be deleted.

## Past password/keys
For the same reason, we cannot enforce that previous version of the database have been permanently deleted. This means that if an old password or key leaks, and the past database is available, then that key is compromized.
