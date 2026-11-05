import { api, setSession } from './api.js';
import { deriveKeys, unlockIdentity } from './crypto.js';
import { $, normaliseUsername, show } from './dom.js';
import { saveIdentity } from './keystore.js';

// Held only in memory between the two login steps; never written to storage.
let pending = null;

const loginForm = $('login-form');
const twofaForm = $('twofa-form');
const statusEl = $('status');
const errorEl = $('error');

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  show(errorEl, '');
  const username = normaliseUsername($('username').value);
  const password = $('password').value;
  $('login-btn').disabled = true;
  try {
    show(statusEl, 'Deriving keys...');
    const { authSecret, wrapKey } = await deriveKeys(password, username);
    $('password').value = '';
    show(statusEl, 'Signing in...');
    const data = await api('/login', { method: 'POST', body: { username, auth_secret: authSecret } });
    pending = { username, wrapKey, preToken: data.pre_2fa_token };
    loginForm.hidden = true;
    twofaForm.hidden = false;
    $('twofa-code').focus();
  } catch (err) {
    show(errorEl, err.message);
  } finally {
    show(statusEl, '');
    $('login-btn').disabled = false;
  }
});

twofaForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  show(errorEl, '');
  if (!pending) {
    show(errorEl, 'Your session expired. Please start again.');
    return;
  }
  $('twofa-btn').disabled = true;
  try {
    const code = $('twofa-code').value.trim();
    const { access_token: token } = await api('/login/verify-2fa', {
      method: 'POST', body: { code }, token: pending.preToken,
    });
    show(statusEl, 'Unlocking your keys...');
    const bundle = await api('/keys/me', { token });
    const identity = await unlockIdentity(bundle.wrapped_private_keys, pending.wrapKey);
    await saveIdentity({ username: pending.username, ...identity });
    setSession(pending.username, token);
    pending = null;
    window.location.href = 'messages.html';
  } catch (err) {
    show(statusEl, '');
    show(errorEl, err.message || 'Could not complete sign-in.');
    if (err.status === 401 && /session|authenticated/i.test(err.message)) pending = null;
  } finally {
    $('twofa-btn').disabled = false;
  }
});
