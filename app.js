import "https://apis.google.com/js/api.js"
import { SharedVault } from './sharedvault.js';


window.VAULT = {};
window.vault_file_id = null;



async function applyVar(node, variable, value) {
    for (let attr in node.dataset) {
        node.dataset[attr] = node.dataset[attr].replaceAll(variable, value);
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
    Array.from(document.getElementsByClassName("splash")).forEach((elmt) => {
        elmt.hidden = true;
    });
    Array.from(document.getElementsByClassName("app")).forEach((elmt) => {
        elmt.hidden = false;
    });
}


async function openFile(file_id) {
    window.vault_file_id = file_id;
    displayApp();
    const response = await gapi.client.drive.files.get({fileId: file_id, alt: "media"})
    const vault_json = JSON.parse(response.body);
    window.VAULT_json = vault_json;  // DEBUG
    window.VAULT = await SharedVault.prototype.fromJSON(vault_json);
    await refreshVault();
}


async function saveFile(file_id, data) {
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
    await saveFile(response.result.id, {users: [], secrets: {}});
    await openFile(response.result.id);
}


async function refreshFiles() {
    const tpl8 = document.getElementById("tpl8_files");
    const list = document.getElementById("ul_files");
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
    const tpl8 = document.getElementById("tpl8_users");
    const list = document.getElementById("ul_users");
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
    const tpl8 = document.getElementById("tpl8_secrets");
    const list = document.getElementById("ul_secrets");
    list.innerHTML = "";
    VAULT.secretIds.forEach((secret_id) => {
        var clone = tpl8.content.cloneNode(true);
        applyVar(clone, "SECRET_ID", secret_id);
        list.appendChild(clone);
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
    Array.from(document.getElementsByClassName("splash")).forEach((elmt) => {
        elmt.hidden = false;
    });
    document.getElementById("btn_create_file").addEventListener("click", createFile);
})