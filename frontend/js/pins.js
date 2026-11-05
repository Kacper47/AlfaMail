// Trust-on-first-use pinning of other users' signing-key fingerprints. If the server
// ever hands out a different key for someone you already talked to (which is exactly
// what a man-in-the-middle would have to do), the UI warns about it.

const prefix = (me, other) => `alfamail.pin.${me}.${other}`;

/** @returns 'new' | 'same' | 'changed' and pins the key on first sight. */
export function checkPin(me, other, fingerprint) {
  try {
    const key = prefix(me, other);
    const known = localStorage.getItem(key);
    if (known === null) {
      localStorage.setItem(key, fingerprint);
      return 'new';
    }
    return known === fingerprint ? 'same' : 'changed';
  } catch {
    return 'new';
  }
}

export function acceptNewPin(me, other, fingerprint) {
  try { localStorage.setItem(prefix(me, other), fingerprint); } catch { /* ignore */ }
}
