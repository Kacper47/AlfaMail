const API_URL = "https://localhost";

function escapeHTML(str) {
    if (!str) return "";
    const p = document.createElement('p');
    p.textContent = str; 
    return p.innerHTML;
}

const fileToBase64 = file => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = () => resolve(reader.result);
    reader.onerror = error => reject(error);
});

// --- UTILS: LOCAL STORAGE MANAGEMENT ---
function saveSession(username, token) {
    localStorage.setItem('username', username);
    localStorage.setItem('access_token', token);
}

function getSession() {
    return {
        username: localStorage.getItem('username'),
        token: localStorage.getItem('access_token')
    };
}

function savePrivateKey(key) {
    localStorage.setItem('private_key', key);
}

function getPrivateKey() {
    return localStorage.getItem('private_key');
}

function logout() {
    localStorage.clear();
    window.location.href = 'index.html';
}

function checkAuth() {
    const { token } = getSession();
    if (!token) {
        window.location.href = 'index.html';
    }
}

// --- AUTHENTICATION (LOGIN) ---
async function login() {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;

    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        
        const data = await response.json();
        if (!response.ok) throw new Error(data.detail);

        if (data.requires_2fa) {
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('2fa-form').style.display = 'block';
        } else if (data.access_token) {
            saveSession(user, data.access_token);
            window.location.href = 'messages.html';
        }
    } catch (error) {
        alert("Login error: " + error.message);
    }
}

async function verifyLogin2FA() {
    const user = document.getElementById('username').value;
    const code = document.getElementById('2fa-code').value;

    try {
        const response = await fetch(`${API_URL}/login/verify-2fa?username=${user}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.detail);

        saveSession(user, data.access_token);
        window.location.href = 'messages.html';
    } catch (error) {
        alert("2FA Verification failed: " + error.message);
    }
}

// --- REGISTRATION FLOW ---
async function register() {
    const user = document.getElementById('reg-username').value;
    const pass = document.getElementById('reg-password').value;

    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });

        const data = await response.json();
        if (!response.ok) {
            let msg = data.detail;
            if (Array.isArray(msg)) msg = msg.map(e => e.msg).join("\n");
            throw new Error(msg || "Registration failed");
        }

        document.getElementById('registration-step').style.display = 'none';
        document.getElementById('2fa-setup-step').style.display = 'block';
        document.getElementById('secret-display').innerText = data.secret;
        localStorage.setItem('temp_reg_username', user);
    } catch (error) {
        alert("Registration Error:\n" + error.message);
    }
}

async function enable2FA() {
    const user = localStorage.getItem('temp_reg_username');
    const code = document.getElementById('setup-code').value;

    try {
        const response = await fetch(`${API_URL}/2fa/enable?username=${user}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code })
        });

        if (!response.ok) throw new Error("Invalid code");
        alert("Account created & 2FA enabled! Please login.");
        window.location.href = 'index.html';
    } catch (error) {
        alert("Error enabling 2FA: " + error.message);
    }
}

// --- MESSAGES LOGIC ---

async function sendMessage() {
    const { username } = getSession();
    const privateKey = getPrivateKey();
    const recipient = document.getElementById('recipient').value;
    const textContent = document.getElementById('msg-content').value;
    const fileInput = document.getElementById('attachment'); 

    if (!privateKey) return alert("Security Error: Identity keys missing.");

    // 1. Pack text and file into a single JSON object
    let payload = {
        text: textContent,
        file: null
    };

    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        if (file.size > 2 * 1024 * 1024) return alert("File too large! Max 2MB.");
        
        const base64Data = await fileToBase64(file);
        payload.file = {
            name: file.name,
            data: base64Data
        };
    }

    const finalContent = JSON.stringify(payload);

    const response = await fetch(`${API_URL}/messages/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            sender_username: username,
            recipient_username: recipient,
            content: finalContent, 
            sender_private_key: privateKey
        })
    });

    if (response.ok) {
        alert("Message & Attachment encrypted and sent!");
        location.reload();
    } else {
        const err = await response.json();
        alert("Error: " + err.detail);
    }
}

async function loadMessages() {
    const { username } = getSession();
    const listDiv = document.getElementById('inbox');
    
    const keyResp = await fetch(`${API_URL}/keys/generate?username=${username}`, { method: 'POST' });
    const keyData = await keyResp.json();
    
    if (!keyResp.ok) {
        listDiv.innerHTML = '<p style="color:red">Security Error: Could not restore identity keys.</p>';
        return;
    }
    
    const privateKey = keyData.private_key;
    savePrivateKey(privateKey);

    const response = await fetch(`${API_URL}/messages/my`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: username,
            private_key: privateKey
        })
    });

    const messages = await response.json();
    listDiv.innerHTML = "";
    
    if (messages.length === 0) {
        listDiv.innerHTML = "<p>Your inbox is empty.</p>";
        return;
    }

    messages.forEach(msg => {
        const div = document.createElement('div');
        div.style.border = "1px solid #ccc";
        div.style.padding = "10px";
        div.style.marginBottom = "5px";
        if (msg.is_read) div.style.opacity = "0.5"; 

        let messageText = "";
        let attachmentHtml = "";

        try {
            const payload = JSON.parse(msg.content);
            messageText = payload.text || "(No text)";
            
            if (payload.file) {
                attachmentHtml = `
                    <div style="margin-top: 10px; padding: 8px; background: #eef; border-radius: 4px;">
                        📎 <b>Attachment:</b> 
                        <a href="${payload.file.data}" download="${payload.file.name}" style="color: blue; font-weight: bold;">
                            Download ${payload.file.name}
                        </a>
                    </div>
                `;
            }
        } catch (e) {
            
            messageText = msg.content;
        }

        const safeSender = escapeHTML(msg.sender_username);
        const safeText = escapeHTML(messageText); 

        div.innerHTML = `
            <b>From:</b> ${safeSender} <br>
            <div style="margin: 10px 0;">${safeText}</div>
            ${attachmentHtml}
            <small style="color: ${msg.signature_valid ? 'green' : 'red'}">
                Signature: ${msg.signature_valid ? "Verified" : "INVALID"}
            </small>
            <div style="margin-top: 10px;">
                <button onclick="deleteMessage(${msg.id})" style="color: red;">Delete</button>
                ${!msg.is_read ? `<button onclick="markRead(${msg.id})">Mark as Read</button>` : ''}
            </div>
        `;
        listDiv.appendChild(div);
    });
}

async function deleteMessage(id) {
    if (!confirm("Are you sure you want to delete this message?")) return;
    const response = await fetch(`${API_URL}/messages/${id}`, { method: 'DELETE' });
    if (response.ok) {
        loadMessages();
    }
}

async function markRead(id) {
    const response = await fetch(`${API_URL}/messages/${id}/read`, { method: 'PATCH' });
    if (response.ok) {
        loadMessages();
    }
}