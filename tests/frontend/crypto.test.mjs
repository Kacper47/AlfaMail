// Run with: node --test tests/frontend
import assert from 'node:assert/strict';
import { before, describe, test } from 'node:test';

import {
  decryptMessage, deriveKeys, encryptMessage, fingerprint, fromB64, generateIdentity,
  sealEnvelope, toB64, unlockIdentity,
} from '../../frontend/js/crypto.js';

const FAST = 1000; // PBKDF2 iterations: low, tests only
const BITS = 2048; // RSA size: small, tests only

async function makeUser(name, password = 'correct horse battery staple!') {
  const keys = await deriveKeys(password, name, FAST);
  const identity = await generateIdentity(keys.wrapKey, BITS);
  const unlocked = await unlockIdentity(identity.wrappedPrivateKeys, keys.wrapKey);
  return { name, keys, identity, ...unlocked };
}

let alice, bob, carol, mallory, directory;
const lookupSig = async (u) => directory[u].identity.sigPublicKey;

before(async () => {
  [alice, bob, carol, mallory] = await Promise.all(
    ['alice', 'bob', 'carol', 'mallory'].map((n) => makeUser(n)),
  );
  directory = { alice, bob, carol, mallory };
});

const encKeys = (...users) => Object.fromEntries(users.map((u) => [u.name, u.identity.encPublicKey]));
const delivered = (sent, sender, recipient, all) => ({
  id: 1, sender_username: sender.name, recipients: all.map((u) => u.name).sort(),
  ciphertext: sent.ciphertext, iv: sent.iv,
  wrapped_key: sent.recipients.find((r) => r.username === recipient.name).wrapped_key,
});

describe('key derivation', () => {
  test('is deterministic and username-bound', async () => {
    const a1 = await deriveKeys('pw', 'alice', FAST);
    const a2 = await deriveKeys('pw', 'Alice ', FAST); // case/space-insensitive username
    const b = await deriveKeys('pw', 'bob', FAST);
    assert.equal(a1.authSecret, a2.authSecret);
    assert.notEqual(a1.authSecret, b.authSecret);
    assert.match(a1.authSecret, /^[A-Za-z0-9_-]{43}$/);
  });
  test('wrapKey is not extractable', async () => {
    const { wrapKey, authSecret } = await deriveKeys('pw', 'alice', FAST);
    assert.equal(wrapKey.extractable, false);
    assert.ok(authSecret.length === 43);
  });
});

describe('identity', () => {
  test('unlock works with the right key and returns non-extractable keys', async () => {
    assert.equal(alice.encPrivateKey.extractable, false);
    assert.equal(alice.sigPrivateKey.extractable, false);
  });
  test('wrong password cannot unlock', async () => {
    const wrong = await deriveKeys('another password', 'alice', FAST);
    await assert.rejects(unlockIdentity(alice.identity.wrappedPrivateKeys, wrong.wrapKey));
  });
  test('uploaded material contains no plaintext private key', () => {
    const blob = JSON.stringify(alice.identity);
    assert.ok(!blob.includes('PRIVATE'));
    assert.deepEqual(Object.keys(alice.identity).sort(), ['encPublicKey', 'sigPublicKey', 'wrappedPrivateKeys']);
  });
  test('fingerprint is stable and key-specific', async () => {
    const f1 = await fingerprint(alice.identity.sigPublicKey);
    assert.equal(f1, await fingerprint(alice.identity.sigPublicKey));
    assert.notEqual(f1, await fingerprint(bob.identity.sigPublicKey));
    assert.match(f1, /^([0-9A-F]{4} ){7}[0-9A-F]{4}$/);
  });
});

describe('messages', () => {
  const attachment = { name: 'note.bin', type: 'application/octet-stream', size: 4, data: toB64(new Uint8Array([1, 2, 3, 4])) };

  test('round trip to several recipients, with attachment, authentic', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob', 'carol'], text: 'héllo 👋 <b>x</b>', attachments: [attachment] },
      alice.sigPrivateKey, encKeys(bob, carol),
    );
    for (const r of [bob, carol]) {
      const res = await decryptMessage(
        delivered(sent, alice, r, [bob, carol]), r.name, r.encPrivateKey, lookupSig,
      );
      assert.equal(res.ok, true);
      assert.equal(res.authentic, true, res.problems.join());
      assert.equal(res.message.text, 'héllo 👋 <b>x</b>');
      assert.deepEqual([...fromB64(res.message.attachments[0].data)], [1, 2, 3, 4]);
    }
  });

  test('server-visible data does not contain the plaintext', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob'], text: 'TOP-SECRET-MARKER', attachments: [] },
      alice.sigPrivateKey, encKeys(bob),
    );
    const wire = JSON.stringify(sent);
    assert.ok(!wire.includes('TOP-SECRET-MARKER'));
    assert.ok(!atob(sent.ciphertext).includes('TOP-SECRET-MARKER'));
    assert.ok(!wire.includes('alice')); // not even the sender name or the signature leak
  });

  test('a non-recipient cannot decrypt', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob'], text: 'x', attachments: [] }, alice.sigPrivateKey, encKeys(bob),
    );
    const stolen = delivered(sent, alice, bob, [bob]);
    const res = await decryptMessage(stolen, 'mallory', mallory.encPrivateKey, lookupSig);
    assert.equal(res.ok, false);
  });

  test('tampered ciphertext is rejected', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob'], text: 'x', attachments: [] }, alice.sigPrivateKey, encKeys(bob),
    );
    const bytes = fromB64(sent.ciphertext);
    bytes[5] ^= 1;
    const res = await decryptMessage(
      { ...delivered(sent, alice, bob, [bob]), ciphertext: toB64(bytes) }, 'bob', bob.encPrivateKey, lookupSig,
    );
    assert.equal(res.ok, false);
  });

  test('forged sender is detected (signature by mallory, claimed alice)', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob'], text: 'pay me', attachments: [] }, mallory.sigPrivateKey, encKeys(bob),
    );
    const res = await decryptMessage(delivered(sent, alice, bob, [bob]), 'bob', bob.encPrivateKey, lookupSig);
    assert.equal(res.ok, true);
    assert.equal(res.authentic, false);
  });

  test('server relabelling the sender is detected', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob'], text: 'x', attachments: [] }, alice.sigPrivateKey, encKeys(bob),
    );
    const res = await decryptMessage(delivered(sent, mallory, bob, [bob]), 'bob', bob.encPrivateKey, lookupSig);
    assert.equal(res.authentic, false);
  });

  test('server adding a recipient the sender did not address is detected', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob'], text: 'x', attachments: [] }, alice.sigPrivateKey, encKeys(bob),
    );
    const msg = { ...delivered(sent, alice, bob, [bob]), recipients: ['bob', 'mallory'] };
    const res = await decryptMessage(msg, 'bob', bob.encPrivateKey, lookupSig);
    assert.equal(res.authentic, false);
  });

  test('a shorter recipient list (others deleted their copy) is still authentic', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob', 'carol'], text: 'x', attachments: [] }, alice.sigPrivateKey, encKeys(bob, carol),
    );
    const msg = delivered(sent, alice, bob, [bob]); // carol deleted her copy
    const res = await decryptMessage(msg, 'bob', bob.encPrivateKey, lookupSig);
    assert.equal(res.authentic, true, res.problems.join());
    assert.deepEqual(res.message.to, ['bob', 'carol']); // what the sender actually signed
  });

  test('forwarding attack: bob re-encrypts alice\'s message to carol -> not authentic for carol', async () => {
    const sent = await encryptMessage(
      { from: 'alice', to: ['bob'], text: 'private to bob', attachments: [] }, alice.sigPrivateKey, encKeys(bob),
    );
    // bob opens the envelope and seals the very same envelope for carol
    const { subtle } = globalThis.crypto;
    const rawCek = await subtle.decrypt({ name: 'RSA-OAEP' }, bob.encPrivateKey, fromB64(sent.recipients[0].wrapped_key));
    const cek = await subtle.importKey('raw', rawCek, 'AES-GCM', false, ['decrypt']);
    const envelope = new TextDecoder().decode(
      await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(sent.iv) }, cek, fromB64(sent.ciphertext)),
    );
    const forwarded = await sealEnvelope(envelope, ['carol'], encKeys(carol));
    const res = await decryptMessage(
      { id: 2, sender_username: 'alice', recipients: ['carol'], ciphertext: forwarded.ciphertext,
        iv: forwarded.iv, wrapped_key: forwarded.recipients[0].wrapped_key },
      'carol', carol.encPrivateKey, lookupSig,
    );
    assert.equal(res.ok, true);
    assert.equal(res.authentic, false);
  });

  test('two encryptions of the same message differ (fresh key + IV)', async () => {
    const args = [{ from: 'alice', to: ['bob'], text: 'same', attachments: [] }, alice.sigPrivateKey, encKeys(bob)];
    const a = await encryptMessage(...args);
    const b = await encryptMessage(...args);
    assert.notEqual(a.ciphertext, b.ciphertext);
    assert.notEqual(a.iv, b.iv);
  });
});
