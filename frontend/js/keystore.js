// Keeps the unlocked, NON-extractable private keys in IndexedDB for the lifetime of the
// login. The browser stores CryptoKey objects without ever exposing the key bytes, so
// not even script running on the page can read them out - it can only ask the browser
// to use them. The password is not stored anywhere.

const DB_NAME = 'alfamail';
const STORE = 'identity';
const RECORD = 'current';

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run(mode, fn) {
  const db = await open();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(request?.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export const saveIdentity = (identity) => run('readwrite', (s) => s.put(identity, RECORD));
export const loadIdentity = () => run('readonly', (s) => s.get(RECORD));
export const clearIdentity = () => run('readwrite', (s) => s.delete(RECORD));
