const DATABASE_NAME = 'vaultx-encrypted-storage';
const DATABASE_VERSION = 1;
const STORE_NAME = 'vaultFiles';
const VAULT_KEY = 'primary-vault';

function openDatabase() {
  if (!('indexedDB' in globalThis)) {
    return Promise.reject(new Error('This browser does not support local encrypted vault storage.'));
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Could not open the browser’s encrypted vault storage.'));
    request.onblocked = () => reject(new Error('Close other VaultX tabs and try again.'));
  });
}

function runTransaction(mode, operation) {
  return openDatabase().then(database => new Promise((resolve, reject) => {
    let settled = false;
    const transaction = database.transaction(STORE_NAME, mode);
    const store = transaction.objectStore(STORE_NAME);
    let request;
    try { request = operation(store); } catch {
      database.close();
      reject(new Error('Could not access the browser’s encrypted vault storage.'));
      return;
    }
    let result;
    if (request) {
      request.onsuccess = () => { result = request.result; };
      request.onerror = () => {
        if (!settled) { settled = true; reject(new Error('Could not access the browser’s encrypted vault storage.')); }
      };
    }
    transaction.oncomplete = () => {
      database.close();
      if (!settled) { settled = true; resolve(result); }
    };
    transaction.onerror = () => {
      database.close();
      if (!settled) { settled = true; reject(new Error('Could not save the encrypted vault.')); }
    };
    transaction.onabort = () => {
      database.close();
      if (!settled) { settled = true; reject(new Error('The encrypted vault update was cancelled.')); }
    };
  }));
}

/** Read the encrypted envelope only. No decrypted content is stored here. */
export function loadEncryptedVault() {
  return runTransaction('readonly', store => store.get(VAULT_KEY));
}

/** Create a first vault only if the slot is empty; never silently replace it. */
export function createEncryptedVaultRecord(envelope) {
  return runTransaction('readwrite', store => store.add(envelope, VAULT_KEY));
}

/** Replace the saved envelope after the caller has authenticated the import. */
export function saveEncryptedVault(envelope) {
  return runTransaction('readwrite', store => store.put(envelope, VAULT_KEY));
}
