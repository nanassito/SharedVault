import "https://apis.google.com/js/api.js"
import { SharedVault } from './sharedvault.js';


window.VAULT = {};
window.VAULT_FILE_ID = null;
const APP = document.getElementById("app");
const TPL8S = document.getElementById("templates");


async function applyVar(node, variable, value) {
    for (let attr in node.dataset) {
        node.dataset[attr] = node.dataset[attr].replaceAll(variable, value);
    }
    if (node.attributes) {
        Array.from(node.attributes).forEach((attr) => {
            attr.value = attr.value.replaceAll(variable, value);
        })
    }
    if (node.childElementCount){
        Array.from(node.children).forEach((child) => {
            applyVar(child, variable, value);
        });
    } else {
        node.textContent = node.textContent.replaceAll(variable, value);
    }
}


function displayApp() {
    document.getElementById("splash").hidden = true;
    APP.hidden = false;
}


async function openFile(file_id) {
    window.VAULT_FILE_ID = file_id;
    const response = await gapi.client.drive.files.get({fileId: file_id, alt: "media"})
    const vault_json = JSON.parse(response.body);
    window.VAULT = await SharedVault.prototype.fromJSON(vault_json);
    await refreshVault();
    displayApp();
}


async function safeFile() {
    await upload(window.VAULT_FILE_ID, await VAULT.toJSON());
}


async function upload(file_id, data) {
    return await gapi.client.request({
        path: "/upload/drive/v3/files/" + file_id,
        method: "PATCH",
        params: {
            uploadType: "media"
        },
        body: JSON.stringify(data),
    })
}


async function createFile() {
    const file_name = prompt("File name:", "sharedvault");
    const response = await gapi.client.drive.files.create({
        uploadType: "media", 
        name: file_name + ".vault",
        mimeType: "application/json",
    })
    await upload(response.result.id, {users: [], secrets: {}});
    await openFile(response.result.id);
}


async function refreshFiles() {
    const tpl8 = TPL8S.querySelector("[data-tpl8='files']");
    const list = document.getElementById("splash").querySelector("[data-tpl8='files']");
    const response = await gapi.client.drive.files.list({
        "q": "fileExtension = 'vault' AND trashed=false",
        "pageSize": 100,
        "fields": "files(id, name, starred)",
    });
    // TODO: Put starred files first.
    response.result.files.map(async file => {
        var clone = tpl8.content.cloneNode(true);
        applyVar(clone, "FILE_ID", file.id);
        applyVar(clone, "FILE_NAME", file.name);
        const node = list.appendChild(clone);
        node.addEventListener("click", async () => {
            await openFile(file.id);
        });
    });
    Array.from(document.getElementsByClassName("btn_open_file")).forEach((elmt) => {
        elmt.addEventListener("click", async (event) => {
            await openFile(event.toElement.dataset.fileId);
        });
    })
}


async function toggleUserLock(event) {
    const user_id = event.toElement.dataset.userId;
    if (event.toElement.dataset.state === "locked"){
        try {
            await VAULT.signIn(user_id, prompt("Password?", "Enter your passphrase."));
        } catch(err) {
            alert(err);
            return;
        }
        event.toElement.dataset.state = "unlocked";
    
    } else {
        await VAULT.signOut(user_id);
        event.toElement.dataset.state = "locked";
    }
}


async function refreshUsers() {
    const tpl8 = TPL8S.querySelector("[data-tpl8='users']");
    const list = APP.querySelector("[data-tpl8='users']");
    list.innerHTML = "";
    VAULT.userIds.forEach((user_id) => {
        var clone = tpl8.content.cloneNode(true);
        applyVar(clone, "USER_ID", user_id);
        list.appendChild(clone);
    });
    Array.from(document.getElementsByClassName("toggle_user_signin")).forEach((button) => {
        button.addEventListener("click", toggleUserLock)
    });
}


async function refreshSecrets() {
    const tpl8_secret = TPL8S.querySelector("[data-tpl8='secrets']");
    const tpl8_key = TPL8S.querySelector("[data-tpl8='keys']");
    const tpl8_key_owner = TPL8S.querySelector("[data-tpl8='key_owners']");
    const ul_secrets = APP.querySelector("[data-tpl8='secrets']");
    ul_secrets.innerHTML = "";
    VAULT.secretIds.forEach(async (secret_id) => {
        const secret = await VAULT.readSecret(secret_id);
        var node_secret = tpl8_secret.content.cloneNode(true);
        secret.keys.forEach((key) => {
            const node_key = tpl8_key.content.cloneNode(true);
            key.forEach((key_owner) => {
                const node_key_owner = tpl8_key_owner.content.cloneNode(true);
                applyVar(node_key_owner, "USER_ID", key_owner);
                node_key.querySelector("[data-tpl8='key_owners']").appendChild(node_key_owner);
            });
            node_secret.querySelector("[data-tpl8='keys']").appendChild(node_key);
        });
        applyVar(node_secret, "SECRET_ID", secret_id);
        applyVar(node_secret, "CONTENT", secret.content);
        applyVar(node_secret, "MIN_KEYS", secret.min_keys);
        ul_secrets.appendChild(node_secret);
    });
}


async function refreshVault() {
    await Promise.all([
        refreshUsers(),
        refreshSecrets(),
    ]);
}


gapi.load("client", async () => {
    await gapi.client.init({
        "discoveryDocs": ["https://www.googleapis.com/discovery/v1/apis/drive/v3/rest"],
        "clientId": "1065488423995-ih2adn3cgrjdqi6ld8tn3opboasa41ur.apps.googleusercontent.com",
        "scope": "https://www.googleapis.com/auth/drive",
    });
    // TODO: Handle popup being blocked.
    await gapi.auth2.getAuthInstance().signIn();
    await refreshFiles();
    document.getElementById("splash").hidden = false;
    document.getElementById("btn_create_file").addEventListener("click", createFile);
    document.getElementById("btn_save_file").addEventListener("click", safeFile);
})