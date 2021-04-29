import * as openpgp from "https://unpkg.com/openpgp@5.0.0-2/dist/openpgp.min.mjs";
// TODO: import crypto.js here.
window.openpgp = openpgp;  // debug


class User {
    constructor(key) {
        this._key = key;
        this._locked = key;
    }
    
    get userId() {
        return this._locked.getUserIDs()[0];
    }
    
    get keyId() {
        return btoa(this._locked.getKeyID().bytes);
    }
    
    get isSignedIn() {
        return this._key.isDecrypted();
    }
    
    async toJSON() {
        return this._locked.armor();
    }
    
    async signIn(passphrase) {
        this._key = await openpgp.decryptKey({privateKey: this._locked, passphrase: passphrase});
    }
    
    async signOut() {
        // > this._key.clearPrivateParams();
        // Error: Error decrypting private key:
        // Private key is encrypted using an insecure S2K function:
        // unsalted MD5
        this._key = this._locked;
    }
}
User.prototype.fromJSON = async function UserFromJSON(data) {
    return new User(await openpgp.readKey({armoredKey: data}));
}


class Secret {
    constructor(content, min_keys, keys, aes_nonce, aes_tag) {
        this._content = content
        this._min_keys = min_keys
        this._keys = keys
        this._aes_nonce = aes_nonce
        this._aes_tag = aes_tag
    }
    
    get minKeys() {
        return this._min_keys;
    }
    
    get totalKeys() {
        return this._keys.length;
    }
    
    async toJSON() {
        return {
            content: this._content,
            min_keys: this._min_keys,
            keys: await Promise.all(
                this._keys.map(async (key) => {
                    const lines = [];
                    const reader = key.armor().getReader();
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) {
                            break;
                        } else {
                            lines.push(value);
                        }
                    }
                    return lines.join("")
                })
            ),
            aes_nonce: this._aes_nonce,
            aes_tag: this._aes_tag,
        }
    }
    
    async getKeysAsPgpMessages() {
        return await Promise.all(this._keys.map(async (key) => {
            return await openpgp.readMessage({armoredMessage: key});
        }));
    }
    
    async getKeysIds() {
        return (await this.getKeysAsPgpMessages()).map(key => {
            return key.getEncryptionKeyIDs()
                .map(keyId => {return btoa(keyId.bytes);})
        });
    }
}
Secret.prototype.fromJSON = async function SecretFromJSON(data) {
    return new Secret(data.content, data.min_keys, Array.from(data.keys), data.aes_nonce, data.aes_tag)
}


export class SharedVault {
    constructor(users, secrets) {
        this._users = users;
        this._secrets = secrets;
    }

    get userIds() {
        return Array.from(this._users.keys());
    }
    
    get secretIds() {
        return Array.from(this._secrets.keys());
    }
    
    genKeyId2UserId() {
        return new Map(
            Array.from(VAULT._users.entries())
                .map(([user_id, user]) => {
                    return [user.keyId, user_id];
                })
        );
    }
    
    async toJSON() {
        return {
            users: await Promise.all(
                Array.from(this._users.values())
                    .map(async (user) => {return await user.toJSON()})
            ),
            secrets: Object.fromEntries(
                await Promise.all(
                    Array.from(VAULT._secrets.keys())
                        .map(async (secret_id) => { 
                            const secret_json = await VAULT._secrets.get(secret_id).toJSON();
                            return [secret_id, secret_json];
                        })
                )
            ),
        }
    }
    
    async signIn(user_id, passphrase) {
        await this._users.get(user_id).signIn(passphrase);
    }
    
    async signOut(user_id) {
        await this._users.get(user_id).signOut();
    }
    
    isUserSignedIn(user_id) {
        return this._users.get(user_id).isSignedIn;
    }
    
    async readSecret(secret_id) {
        const secret = this._secrets.get(secret_id);
        const private_keys = []
        this._users.forEach((user, user_id) => {
            if (user.isSignedIn) {
                private_keys.push(user._key);
            }
        });
        const shares = [];
        await Promise.all(
            (await secret.getKeysAsPgpMessages()).map(async (msg) => {
                shares.push(await openpgp.decrypt({message: msg, privateKeys: private_keys}));
            })
        );
        var content = "";
        var is_locked = false;
        const keyId2UserId = this.genKeyId2UserId();
        return {
            is_locked: is_locked,
            content: content,
            min_keys: secret.minKeys,
            keys: (await secret.getKeysIds()).map((keyIds) => {
                return keyIds.map((keyId) => { return keyId2UserId.get(keyId); });
            }),
        }
    }
    
    async createUser(user_id, passphrase) {
        if (this.userIds.includes(user_id)){ 
            alert("Userid " + user_id + " is already taken.");
            return;
        }
        const { key, privateKeyArmored } = await openpgp.generateKey({
            userIDs: [{name: user_id}],
            passphrase: passphrase,
        });
        this._users.set(key.getUserIDs()[0], await User.prototype.fromJSON(privateKeyArmored)); 
        await this.signIn(user_id, passphrase);
    }
}

SharedVault.prototype.fromJSON = async function SharedVaultFromJSON(data) {
    const users = new Map();
    await Promise.all(
        data.users.map(async key => {
            var user = await User.prototype.fromJSON(key);
            users.set(user.userId, user);
        })
    );
    const secrets = new Map();
    for (let secret_id in data.secrets){
        secrets.set(secret_id, await Secret.prototype.fromJSON(data.secrets[secret_id]));
    }
    return new SharedVault(users, secrets);
}

window.debug = async function(){
    console.log("breakpoint");
}
