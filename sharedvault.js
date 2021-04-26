import * as openpgp from "https://unpkg.com/openpgp@5.0.0-1/dist/openpgp.min.mjs";
// TODO: import crypto.js here.


class User {
    constructor(armored, key) {
        this._armored = armored;
        this._key = key;
    }
    
    get userId() {
        return this._key.getUserIds()[0];
    }
    
    get keyId() {
        return btoa(this._key.getKeyId().bytes);
    }
    
    async toJSON() {
        return this._armored;
    }
    
    async signIn(passphrase) {
        await this._key.decrypt(passphrase);
    }
    
    async signOut() {
        this._key.clearPrivateParams();
        // BUG: when clearing, we can't sign back in anymore, so we reload the key.
        this._key = await openpgp.readKey({ armoredKey: this._armored });
    }
}
User.prototype.fromJSON = async function UserFromJSON(data) {
    const key = await openpgp.readKey({ armoredKey: data });
    return new User(data, key);
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
    
    get keysIds() {
        return this._keys.map(key => {
            return key.getEncryptionKeyIds()
                .map(keyId => {return btoa(keyId.bytes);})
        });
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
}
Secret.prototype.fromJSON = async function SecretFromJSON(data) {
    const keys = await Promise.all(
        data.keys.map(async key => {
            return await openpgp.readMessage({ armoredMessage: key });
        })
    );
    return new Secret(data.content, data.min_keys, keys, data.aes_nonce, data.aes_tag)
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
    
    async readSecret(secret_id) {
        const secret = this._secrets.get(secret_id);
        var is_locked = true;
        const keyId2UserId = this.genKeyId2UserId();
        return {
            is_locked: is_locked,
            content: null,
            min_keys: secret.minKeys,
            keys: secret.keysIds.map((keyIds) => {
                return keyIds.map((keyId) => { return keyId2UserId.get(keyId); });
            }),
        }
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
