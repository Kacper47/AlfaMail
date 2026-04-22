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

function saveSession(username, token) {
    sessionStorage.setItem('username', username);
    sessionStorage.setItem('access_token', token);
}

function getSession() {
    return {
        username: sessionStorage.getItem('username'),
        token: sessionStorage.getItem('access_token')
    };
}

function getAuthHeaders() {
    const { token } = getSession();
    if (!token) return { 'Content-Type': 'application/json' };
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
}

function savePrivateKey(key) {
    sessionStorage.setItem('private_key', key);
}

function getPrivateKey() {
    return sessionStorage.getItem('private_key');
}

function logout() {
    sessionStorage.clear();
    localStorage.removeItem('temp_reg_username');
    window.location.href = 'index.html';
}

function checkAuth() {
    const { token } = getSession();
    if (!token) {
        window.location.href = 'index.html';
    }
}

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

        sessionStorage.setItem('encryption_password', pass);

        if (data.requires_2fa && data.pre_2fa_token) {
            sessionStorage.setItem('pre_2fa_token', data.pre_2fa_token);
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
    const pre2faToken = sessionStorage.getItem('pre_2fa_token');

    if (!pre2faToken) {
        alert("2FA session expired. Please login again.");
        return;
    }

    try {
        const response = await fetch(`${API_URL}/login/verify-2fa`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${pre2faToken}`
            },
            body: JSON.stringify({ code: code })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.detail);

        sessionStorage.removeItem('pre_2fa_token');
        saveSession(user, data.access_token);
        window.location.href = 'messages.html';
    } catch (error) {
        alert("2FA Verification failed: " + error.message);
    }
}

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
        document.getElementById('qrcode').innerHTML = "";
        new QRCode(document.getElementById("qrcode"), {
            text: data.otpauth_uri,
            width: 160,
            height: 160,
            colorDark: "#000000",
            colorLight: "#ffffff",
            correctLevel: QRCode.CorrectLevel.H
        });
        localStorage.setItem('temp_reg_username', user);
        sessionStorage.setItem('encryption_password', pass);
    } catch (error) {
        alert("Registration Error:\n" + error.message);
    }
}

async function enable2FA() {
    const user = localStorage.getItem('temp_reg_username');
    const code = document.getElementById('setup-code').value;
    const pass = sessionStorage.getItem('encryption_password');

    try {
        const response = await fetch(`${API_URL}/2fa/enable`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass, code: code })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.detail || "Invalid code");

        localStorage.removeItem('temp_reg_username');
        alert("Account created & 2FA enabled! Please login.");
        window.location.href = 'index.html';
    } catch (error) {
        alert("Error enabling 2FA: " + error.message);
    }
}

async function sendMessage() {
    const { username } = getSession();
    const privateKey = getPrivateKey();
    const recipient = document.getElementById('recipient').value;
    const textContent = document.getElementById('msg-content').value;
    const fileInput = document.getElementById('attachment');

    if (!privateKey) return alert("Security Error: Identity keys missing.");

    const password = sessionStorage.getItem('encryption_password');
    if (!password) {
        alert("Session expired. Please logout and login again to unlock keys.");
        return;
    }

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
        headers: getAuthHeaders(),
        body: JSON.stringify({
            sender_username: username,
            recipient_username: recipient,
            content: finalContent,
            sender_private_key: privateKey,
            password: password
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
    const listDiv = document.getElementById('inbox');

    const password = sessionStorage.getItem('encryption_password');
    if (!password) {
        listDiv.innerHTML = '<p style="color:red">Encryption key missing. Please relogin.</p>';
        return;
    }

    const keyResp = await fetch(`${API_URL}/keys/generate`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ password: password })
    });
    const keyData = await keyResp.json();

    if (!keyResp.ok) {
        listDiv.innerHTML = '<p style="color:red">Security Error: Could not restore identity keys.</p>';
        return;
    }

    const privateKey = keyData.private_key;
    savePrivateKey(privateKey);

    const response = await fetch(`${API_URL}/messages/my`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
            private_key: privateKey,
            password: password
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

            if (payload.file && typeof payload.file.data === 'string' && payload.file.data.startsWith('data:')) {
                const safeFileName = escapeHTML(payload.file.name || 'attachment');
                const safeFileData = payload.file.data;
                attachmentHtml = `
                    <div style="margin-top: 10px; padding: 8px; background: #eef; border-radius: 4px;">
                        <b>Attachment:</b>
                        <a href="${safeFileData}" download="${safeFileName}" style="color: blue; font-weight: bold;">
                            Download ${safeFileName}
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
    const response = await fetch(`${API_URL}/messages/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders()
    });
    if (response.ok) {
        loadMessages();
    }
}

async function markRead(id) {
    const response = await fetch(`${API_URL}/messages/${id}/read`, {
        method: 'PATCH',
        headers: getAuthHeaders()
    });
    if (response.ok) {
        loadMessages();
    }
}
