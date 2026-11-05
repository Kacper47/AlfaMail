import { api, ApiError, clearSession, getSession } from './api.js';
import { decryptMessage, encryptMessage, fingerprint, fromB64, toB64 } from './crypto.js';
import { $, el, normaliseUsername, USERNAME_RE } from './dom.js';
import { clearIdentity, loadIdentity } from './keystore.js';
import { acceptNewPin, checkPin } from './pins.js';

const MAX_RECIPIENTS = 10;
const MAX_FILES = 5;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES = 3 * 1024 * 1024;

let me = null; // { username, encPrivateKey, sigPrivateKey }
const sigKeyCache = new Map(); // username -> base64 SPKI

// ---------- session ----------

async function logout() {
  clearSession();
  try { await clearIdentity(); } catch { /* ignore */ }
  window.location.href = 'index.html';
}

async function init() {
  const { username, token } = getSession();
  const identity = token && username ? await loadIdentity().catch(() => null) : null;
  if (!identity || identity.username !== username) {
    await logout();
    return;
  }
  me = identity;
  $('whoami').textContent = username;
  $('logout-btn').addEventListener('click', logout);
  $('refresh-btn').addEventListener('click', loadMessages);
  $('compose-form').addEventListener('submit', sendMessage);
  await Promise.all([loadMessages(), loadActivity()]);
}

/** Run an API call; on an expired/invalid session go back to the login page. */
async function guarded(fn) {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) await logout();
    throw err;
  }
}

// ---------- keys of other users ----------

async function getPublicKeys(username) {
  const keys = await guarded(() => api(`/users/${encodeURIComponent(username)}/public-keys`));
  sigKeyCache.set(username, keys.sig_public_key);
  return keys;
}

async function getSigKey(username) {
  return sigKeyCache.get(username) ?? (await getPublicKeys(username)).sig_public_key;
}

// ---------- sending ----------

function safeFileName(name) {
  const cleaned = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').replace(/^\.+/, '_').slice(0, 100);
  return cleaned || 'attachment';
}

async function readAttachments(fileList) {
  const files = [...fileList];
  if (files.length > MAX_FILES) throw new Error(`At most ${MAX_FILES} attachments are allowed.`);
  let total = 0;
  const out = [];
  for (const file of files) {
    if (file.size > MAX_FILE_BYTES) throw new Error(`"${file.name}" is larger than 2 MB.`);
    total += file.size;
    if (total > MAX_TOTAL_BYTES) throw new Error('Attachments are larger than 3 MB in total.');
    out.push({
      name: safeFileName(file.name),
      type: file.type || 'application/octet-stream',
      size: file.size,
      data: toB64(new Uint8Array(await file.arrayBuffer())),
    });
  }
  return out;
}

function parseRecipients(raw) {
  const names = [...new Set(raw.split(/[\s,;]+/).map(normaliseUsername).filter(Boolean))];
  if (names.length === 0) throw new Error('Enter at least one recipient.');
  if (names.length > MAX_RECIPIENTS) throw new Error(`At most ${MAX_RECIPIENTS} recipients are allowed.`);
  const bad = names.find((n) => !USERNAME_RE.test(n));
  if (bad) throw new Error(`"${bad.slice(0, 40)}" is not a valid username.`);
  return names;
}

async function sendMessage(event) {
  event.preventDefault();
  const status = $('send-status');
  const button = $('send-btn');
  status.textContent = '';
  button.disabled = true;
  try {
    const to = parseRecipients($('recipients').value);
    const text = $('body').value;
    const attachments = await readAttachments($('files').files);

    status.textContent = 'Fetching recipients\' keys...';
    const encKeys = {};
    for (const name of to) {
      let keys;
      try {
        keys = await getPublicKeys(name);
      } catch (err) {
        if (err.status === 404) throw new Error(`User "${name}" was not found.`);
        throw err;
      }
      encKeys[name] = keys.enc_public_key;
      const fp = await fingerprint(keys.sig_public_key);
      if (checkPin(me.username, name, fp) === 'changed') {
        const proceed = window.confirm(
          `WARNING: the signing key of "${name}" has changed since you last wrote to them.\n` +
          `New fingerprint: ${fp}\n\nThis can happen if they re-registered, but it can also mean someone is ` +
          'impersonating them. Verify the fingerprint with them through another channel.\n\nSend anyway?',
        );
        if (!proceed) throw new Error('Sending cancelled.');
        acceptNewPin(me.username, name, fp);
      }
    }

    status.textContent = 'Encrypting...';
    const sealed = await encryptMessage(
      { from: me.username, to, text, attachments }, me.sigPrivateKey, encKeys,
    );
    status.textContent = 'Sending...';
    await guarded(() => api('/messages/send', { method: 'POST', body: sealed }));

    $('compose-form').reset();
    status.textContent = 'Sent (end-to-end encrypted).';
  } catch (err) {
    status.textContent = err.message || 'Could not send the message.';
  } finally {
    button.disabled = false;
  }
}

// ---------- reading ----------

function formatSize(bytes) {
  return bytes < 1024 ? `${bytes} B` : bytes < 1048576 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / 1048576).toFixed(1)} MB`;
}

function downloadAttachment(att) {
  // Always served as an opaque binary blob and never opened inline, so an attachment
  // can neither run as a page nor be sniffed as HTML.
  const url = URL.createObjectURL(new Blob([fromB64(att.data)], { type: 'application/octet-stream' }));
  const link = el('a', { href: url, download: safeFileName(att.name) });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

async function renderMessage(msg) {
  const card = el('article', { class: `msg ${msg.is_read ? 'read' : 'unread'}` });
  const result = await decryptMessage(msg, me.username, me.encPrivateKey, getSigKey);
  const when = new Date(msg.created_at + 'Z').toLocaleString();

  if (!result.ok) {
    card.append(
      el('div', {}, el('strong', { text: `From: ${msg.sender_username}` }), ` - ${when}`),
      el('p', { class: 'banner', text: result.error }),
    );
  } else {
    const { message, authentic, problems } = result;
    const header = el('div', { class: 'row' },
      el('div', {}, el('strong', { text: `From: ${message.from}` }), el('span', { class: 'muted', text: ` - ${when}` })),
      el('span', { class: `badge ${authentic ? 'ok' : 'bad'}`, text: authentic ? 'Signature verified' : 'NOT AUTHENTIC' }),
    );
    card.append(header, el('div', { class: 'muted', text: `To: ${message.to.join(', ')}` }));
    if (!authentic) problems.forEach((p) => card.append(el('p', { class: 'banner', text: p })));

    card.append(el('div', { class: 'body', text: message.text }));

    if (message.attachments.length) {
      const box = el('div', { class: 'attachments' }, el('strong', { text: 'Attachments' }));
      for (const att of message.attachments) {
        const label = `${safeFileName(att.name)} (${formatSize(fromB64(att.data).length)})`;
        const button = el('button', { type: 'button', text: `Download ${label}` });
        button.disabled = !authentic;
        button.addEventListener('click', () => downloadAttachment(att));
        box.append(el('div', {}, button));
      }
      if (!authentic) box.append(el('div', { class: 'muted', text: 'Downloads are disabled because the message could not be verified.' }));
      card.append(box);
    }

    try {
      const fp = await fingerprint(await getSigKey(msg.sender_username));
      const pin = checkPin(me.username, msg.sender_username, fp);
      const note = pin === 'changed' ? ' - CHANGED since you first saw it!' : pin === 'new' ? ' - first seen' : '';
      card.append(el('div', { class: `muted fp${pin === 'changed' ? ' error' : ''}`, text: `Sender key: ${fp}${note}` }));
    } catch { /* sender key unavailable: already reflected in the signature result */ }
  }

  const actions = el('div', { class: 'actions' });
  if (!msg.is_read) {
    actions.append(el('button', { type: 'button', text: 'Mark as read', onclick: () => act(() => api(`/messages/${msg.id}/read`, { method: 'PATCH' })) }));
  }
  actions.append(el('button', {
    type: 'button', class: 'danger', text: 'Delete',
    onclick: () => { if (window.confirm('Delete this message permanently?')) act(() => api(`/messages/${msg.id}`, { method: 'DELETE' })); },
  }));
  card.append(actions);
  return card;
}

async function act(fn) {
  try { await guarded(fn); } catch { /* shown by reload below */ }
  await loadMessages();
}

async function loadMessages() {
  const status = $('inbox-status');
  const list = $('inbox');
  status.textContent = 'Loading...';
  try {
    const messages = await guarded(() => api('/messages'));
    const cards = [];
    for (const msg of messages) cards.push(await renderMessage(msg));
    list.replaceChildren(...cards);
    status.textContent = messages.length ? '' : 'Your inbox is empty.';
  } catch (err) {
    status.textContent = err.message || 'Could not load messages.';
  }
}

async function loadActivity() {
  try {
    const rows = await guarded(() => api('/account/activity'));
    const labels = { login_success: 'Signed in', login_failed: 'Failed sign-in attempt', '2fa_failed': 'Wrong 2FA code' };
    $('activity').replaceChildren(...rows.map((r) => el('tr', {},
      el('td', { text: new Date(r.timestamp + 'Z').toLocaleString() }),
      el('td', { text: labels[r.event_type] ?? r.event_type }),
      el('td', { text: r.ip_address ?? '' }),
    )));
  } catch { /* non-essential */ }
}

init();
