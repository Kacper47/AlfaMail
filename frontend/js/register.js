import { api } from './api.js';
import { deriveKeys, generateIdentity } from './crypto.js';
import { $, el, normaliseUsername, show, USERNAME_RE } from './dom.js';
import { assessPassword } from './strength.js';

const registerForm = $('register-form');
const setupForm = $('setup-form');
const statusEl = $('status');
const errorEl = $('error');

// Held only in memory until 2FA is activated.
let account = null;

function refreshMeter() {
  const result = assessPassword($('reg-password').value, $('reg-username').value);
  $('meter').className = `meter s${result.score}`;
  $('strength-label').textContent = $('reg-password').value
    ? `Strength: ${result.label}` : 'Enter a password';
  $('issues').replaceChildren(...result.issues.map((text) => el('li', { text })));
  return result;
}
$('reg-password').addEventListener('input', refreshMeter);
$('reg-username').addEventListener('input', refreshMeter);

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  show(errorEl, '');

  const username = normaliseUsername($('reg-username').value);
  const password = $('reg-password').value;
  if (!USERNAME_RE.test(username)) {
    show(errorEl, 'Username: 3-32 characters, lowercase letters, digits, _ . - (start with a letter or digit).');
    return;
  }
  if (password !== $('reg-password2').value) {
    show(errorEl, 'The passwords do not match.');
    return;
  }
  if (!refreshMeter().acceptable) {
    show(errorEl, 'Please choose a stronger password.');
    return;
  }

  $('register-btn').disabled = true;
  try {
    show(statusEl, 'Deriving keys...');
    const { authSecret, wrapKey } = await deriveKeys(password, username);
    show(statusEl, 'Generating your encryption keys (this can take a few seconds)...');
    const identity = await generateIdentity(wrapKey);
    show(statusEl, 'Creating account...');
    const data = await api('/register', {
      method: 'POST',
      body: {
        username,
        auth_secret: authSecret,
        enc_public_key: identity.encPublicKey,
        sig_public_key: identity.sigPublicKey,
        wrapped_private_keys: identity.wrappedPrivateKeys,
      },
    });
    account = { username, authSecret };
    $('reg-password').value = '';
    $('reg-password2').value = '';

    registerForm.hidden = true;
    setupForm.hidden = false;
    $('secret').textContent = data.secret;
    $('qrcode').replaceChildren();
    new QRCode($('qrcode'), { text: data.otpauth_uri, width: 168, height: 168, correctLevel: QRCode.CorrectLevel.M });
    $('setup-code').focus();
  } catch (err) {
    show(errorEl, err.message);
  } finally {
    show(statusEl, '');
    $('register-btn').disabled = false;
  }
});

setupForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  show(errorEl, '');
  if (!account) return;
  $('setup-btn').disabled = true;
  try {
    await api('/2fa/enable', {
      method: 'POST',
      body: { username: account.username, auth_secret: account.authSecret, code: $('setup-code').value.trim() },
    });
    account = null;
    window.location.href = 'index.html';
  } catch (err) {
    show(errorEl, err.message);
  } finally {
    $('setup-btn').disabled = false;
  }
});
