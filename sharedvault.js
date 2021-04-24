import * as openpgp from "https://unpkg.com/openpgp@5.0.0-1/dist/openpgp.min.mjs";
// TODO: import crypto.js here.


class Secret {
    constructor(content, min_keys, keys, aes_nonce, aes_tag){
        this.content = content
        this.min_keys = min_keys
        this.keys = keys
        this.aes_nonce = aes_nonce
        this.aes_tag = aes_tag
    }
}
Secret.prototype.fromJSON = async function SecretfromJSON(data) {
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

    get user_ids() {
        return Array.from(this._users.keys());
    }
    
    get secret_ids() {
        return Array.from(this._secrets.keys());
    }
    
    async signin(user_id, passphrase) {
        await this._users.get(user_id).decrypt(passphrase);
    }
    
    async signout(user_id) {
        this._users.get(user_id).clearPrivateParams();
    }
}

SharedVault.prototype.fromJSON = async function SharedVaultfromJSON(data) {
    const users = new Map();
    await Promise.all(
        data.users.map(async key => {
            key = await openpgp.readKey({ armoredKey: key });
            users.set(key.getUserIds()[0], key);
        })
    );
    const secrets = new Map();
    for (let secret_id in data.secrets){
        secrets.set(secret_id, await Secret.prototype.fromJSON(data.secrets[secret_id]));
    }
    return new SharedVault(users, secrets);
}
