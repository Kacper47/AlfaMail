// End-to-end encryption primitives (Web Crypto API). Nothing in this file talks to
// the network: it only turns plaintext into ciphertext and back. The server never
// sees any key or plaintext produced here.
//
//  password --PBKDF2--> 64 bytes ─┬─ first 32 bytes: authSecret  (sent to the server for login)
//                                 └─ last  32 bytes: wrapKey     (stays in the browser)
//
//  Each user owns two RSA key pairs: RSA-OAEP (receive) and RSA-PSS (sign). Their
//  private halves are stored on the server only after being encrypted with wrapKey.
//
//  Message = AES-256-GCM(envelope) with a random key, that key wrapped (RSA-OAEP)
//  once per recipient. envelope = { m: <signed JSON>, s: <RSA-PSS signature of m> }.

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const KDF_ITERATIONS = 600_000; // OWASP guidance for PBKDF2-HMAC-SHA256
export const RSA_BITS = 3072;
const PSS_SALT_LENGTH = 32; // = SHA-256 output size
const PROTOCOL_VERSION = 1;

// ---------- base64 helpers ----------

export function toB64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let i = 0; i < u8.length; i += 0x8000) {
    binary += String.fromCharCode(...u8.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromB64(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function toB64Url(bytes) {
  return toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------- password -> (authSecret, wrapKey) ----------

export async function deriveKeys(password, username, iterations = KDF_ITERATIONS) {
  const salt = new Uint8Array(
    await subtle.digest('SHA-256', encoder.encode('alfamail-v1|' + username.trim().toLowerCase())),
  );
  const material = await subtle.importKey(
    'raw', encoder.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits'],
  );
  const bits = new Uint8Array(
    await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, material, 512),
  );
  const authSecret = toB64Url(bits.slice(0, 32));
  const wrapKey = await subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  bits.fill(0);
  return { authSecret, wrapKey };
}

// ---------- AES-GCM helper ----------

async function aesGcmEncrypt(key, plaintext) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
  return { iv, ct };
}

// ---------- identity (key pairs) ----------

export async function generateIdentity(wrapKey, bits = RSA_BITS) {
  const exp = new Uint8Array([1, 0, 1]);
  const encPair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: bits, publicExponent: exp, hash: 'SHA-256' },
    true, ['encrypt', 'decrypt'],
  );
  const sigPair = await subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: bits, publicExponent: exp, hash: 'SHA-256' },
    true, ['sign', 'verify'],
  );
  const bundle = JSON.stringify({
    enc: toB64(await subtle.exportKey('pkcs8', encPair.privateKey)),
    sig: toB64(await subtle.exportKey('pkcs8', sigPair.privateKey)),
  });
  const { iv, ct } = await aesGcmEncrypt(wrapKey, encoder.encode(bundle));
  return {
    encPublicKey: toB64(await subtle.exportKey('spki', encPair.publicKey)),
    sigPublicKey: toB64(await subtle.exportKey('spki', sigPair.publicKey)),
    wrappedPrivateKeys: { iv: toB64(iv), ct: toB64(ct) },
  };
}

/** Decrypt the key bundle from the server. Throws if wrapKey is wrong. Returned keys are NON-extractable. */
export async function unlockIdentity(wrapped, wrapKey) {
  const plain = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(wrapped.iv) }, wrapKey, fromB64(wrapped.ct),
  );
  const bundle = JSON.parse(decoder.decode(plain));
  return {
    encPrivateKey: await subtle.importKey(
      'pkcs8', fromB64(bundle.enc), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt'],
    ),
    sigPrivateKey: await subtle.importKey(
      'pkcs8', fromB64(bundle.sig), { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign'],
    ),
  };
}

function importPublicKey(spkiB64, kind) {
  const alg = kind === 'enc' ? { name: 'RSA-OAEP', hash: 'SHA-256' } : { name: 'RSA-PSS', hash: 'SHA-256' };
  return subtle.importKey('spki', fromB64(spkiB64), alg, false, kind === 'enc' ? ['encrypt'] : ['verify']);
}

/** Human-comparable fingerprint of a public key (SHA-256, first 128 bits, in groups of 4 hex digits). */
export async function fingerprint(spkiB64) {
  const hash = new Uint8Array(await subtle.digest('SHA-256', fromB64(spkiB64)));
  const hex = [...hash.slice(0, 16)].map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g).join(' ').toUpperCase();
}

// ---------- messages ----------

/**
 * Encrypt an already-built envelope for `usernames`.
 * `recipientEncKeys` maps username -> base64 SPKI of their RSA-OAEP key.
 */
export async function sealEnvelope(envelopeString, usernames, recipientEncKeys) {
  const cek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const { iv, ct } = await aesGcmEncrypt(cek, encoder.encode(envelopeString));
  const rawCek = await subtle.exportKey('raw', cek);
  const recipients = [];
  for (const username of usernames) {
    const pub = await importPublicKey(recipientEncKeys[username], 'enc');
    const wrapped = await subtle.encrypt({ name: 'RSA-OAEP' }, pub, rawCek);
    recipients.push({ username, wrapped_key: toB64(wrapped) });
  }
  return { ciphertext: toB64(ct), iv: toB64(iv), recipients };
}

/**
 * Sign and encrypt a message. The signature covers sender, recipient list, timestamp,
 * text AND attachments, and is itself encrypted - the server cannot read or test it.
 */
export async function encryptMessage({ from, to, text, attachments }, sigPrivateKey, recipientEncKeys) {
  const recipients = [...new Set(to)].sort();
  const signed = JSON.stringify({
    v: PROTOCOL_VERSION, from, to: recipients, ts: new Date().toISOString(), text, attachments,
  });
  const signature = await subtle.sign(
    { name: 'RSA-PSS', saltLength: PSS_SALT_LENGTH }, sigPrivateKey, encoder.encode(signed),
  );
  const envelope = JSON.stringify({ m: signed, s: toB64(signature) });
  return sealEnvelope(envelope, recipients, recipientEncKeys);
}

const isString = (x) => typeof x === 'string';

/**
 * Decrypt and verify one message as returned by GET /messages.
 * `getSigPublicKey(username)` must resolve to the sender's base64 SPKI signing key.
 * Returns { ok:false, error } if it cannot be decrypted, otherwise
 * { ok:true, authentic, problems[], message:{from,to,ts,text,attachments} }.
 */
export async function decryptMessage(serverMsg, myUsername, encPrivateKey, getSigPublicKey) {
  let envelope;
  try {
    const rawCek = await subtle.decrypt(
      { name: 'RSA-OAEP' }, encPrivateKey, fromB64(serverMsg.wrapped_key),
    );
    const cek = await subtle.importKey('raw', rawCek, 'AES-GCM', false, ['decrypt']);
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(serverMsg.iv) }, cek, fromB64(serverMsg.ciphertext),
    );
    envelope = JSON.parse(decoder.decode(plain));
    if (!envelope || !isString(envelope.m) || !isString(envelope.s)) throw new Error('bad envelope');
  } catch {
    return { ok: false, error: 'This message could not be decrypted.' };
  }

  const problems = [];
  let signed;
  try {
    signed = JSON.parse(envelope.m);
    const okShape =
      signed && signed.v === PROTOCOL_VERSION && isString(signed.from) && isString(signed.ts) &&
      isString(signed.text) && Array.isArray(signed.to) && signed.to.every(isString) &&
      Array.isArray(signed.attachments) &&
      signed.attachments.every((a) => a && isString(a.name) && isString(a.type) && isString(a.data));
    if (!okShape) throw new Error('bad shape');
  } catch {
    return { ok: false, error: 'This message has an invalid format.' };
  }

  // 1. cryptographic signature by the claimed sender
  let signatureValid = false;
  try {
    const sigKey = await importPublicKey(await getSigPublicKey(serverMsg.sender_username), 'sig');
    signatureValid = await subtle.verify(
      { name: 'RSA-PSS', saltLength: PSS_SALT_LENGTH }, sigKey, fromB64(envelope.s), encoder.encode(envelope.m),
    );
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) problems.push('The signature does not match the sender.');

  // 2. the signed content must agree with what the server told us
  if (signed.from !== serverMsg.sender_username) problems.push('The signed sender differs from the delivered sender.');
  if (!signed.to.includes(myUsername)) problems.push('This message was not signed as addressed to you (possible forwarding).');
  // The server lists the recipients that still hold a copy; that list shrinks when a
  // recipient deletes their copy, so it may be a subset of the signed list - but the
  // server must never be able to add someone the sender did not address.
  if (!serverMsg.recipients.every((name) => signed.to.includes(name))) {
    problems.push('The recipient list was altered.');
  }

  return {
    ok: true,
    authentic: problems.length === 0,
    problems,
    message: { from: signed.from, to: signed.to, ts: signed.ts, text: signed.text, attachments: signed.attachments },
  };
}
