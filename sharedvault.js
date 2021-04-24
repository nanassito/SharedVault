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
    
    async toJSON() {
        return this._armored;
    }
    
    async signIn(passphrase) {
        await this._key.decrypt(passphrase);
    }
    
    async signOut() {
        this._key.clearPrivateParams();
        // BUG: when clearing, we can't signin again, so we reload the key.
        this._key = await openpgp.readKey({ armoredKey: this._armored });
    }
}
User.prototype.fromJSON = async function UserFromJSON(data) {
    const key = await openpgp.readKey({ armoredKey: data });
    return new User(data, key);
}


class Secret {
    constructor(content, min_keys, keys, aes_nonce, aes_tag) {
        this.content = content
        this.min_keys = min_keys
        this.keys = keys
        this.aes_nonce = aes_nonce
        this.aes_tag = aes_tag
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
    
    async toJSON() {
        return {
            users: await Promise.all(
                Array.from(this._users.values())
                    .map(async (user) => {return await user.toJSON()})
            ),
            //secrets: this._secrets.
        }
    }
    
    async signIn(user_id, passphrase) {
        await this._users.get(user_id).signIn(passphrase);
    }
    
    async signOut(user_id) {
        await this._users.get(user_id).signOut();
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
