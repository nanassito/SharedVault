import "https://apis.google.com/js/api.js"
import { SharedVault } from './sharedvault.js';


window.VAULT = {};
window.vault_file_id = null;


async function apply_var(node, variable, value) {
    for (let attr in node.dataset) {
        node.dataset[attr] = node.dataset[attr].replaceAll(variable, value);
    }
    if (node.childElementCount){
        Array.from(node.children).forEach((child) => {
            apply_var(child, variable, value);
        });
    } else {
        node.textContent = node.textContent.replaceAll(variable, value);
    }
}


function display_app(){
    Array.from(document.getElementsByClassName("splash")).forEach((elmt) => {
        elmt.hidden = true;
    });
    Array.from(document.getElementsByClassName("app")).forEach((elmt) => {
        elmt.hidden = false;
    });
}


async function open_file_event(event) {
    await open_file(event.toElement.dataset.fileId);
}


async function open_file(file_id) {
    window.vault_file_id = file_id;
    display_app();
    const response = await gapi.client.drive.files.get({fileId: file_id, alt: "media"})
    window.VAULT = await SharedVault.prototype.fromJSON(response.body);
}


async function create_file() {
    const file_name = prompt("File name:", "sharedvault");
    const response = await gapi.client.drive.files.create({
        uploadType: "media", 
        resource: {users: [], secrets: {}}, 
        name: file_name + ".vault",
    })
    await open_file(response.result.id);
}


async function refresh_files() {
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
        apply_var(clone, "FILE_ID", file.id);
        apply_var(clone, "FILE_NAME", file.name);
        list.appendChild(clone);
    });

}


gapi.load("client", async () => {
    await gapi.client.init({
        "discoveryDocs": ["https://www.googleapis.com/discovery/v1/apis/drive/v3/rest"],
        "clientId": "1065488423995-ih2adn3cgrjdqi6ld8tn3opboasa41ur.apps.googleusercontent.com",
        "scope": "https://www.googleapis.com/auth/drive",
    });
    // TODO: Handle popup being blocked.
    await gapi.auth2.getAuthInstance().signIn();
    await refresh_files();
})