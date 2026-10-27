/* VaultX encryption primitives. All key material remains in this module's
 * short-lived function scope; callers only receive plaintext after GCM verifies. */
const FORMAT = 'vaultx-encrypted-vault';
const VERSION = 1;
const KDF_ITERATIONS = 600_000;
const MIN_ACCEPTED_ITERATIONS = 600_000;
const MAX_ACCEPTED_ITERATIONS = 2_000_000;
const MAX_FILE_BYTES = 20 * 1024 * 1024;
const encoder = new TextEncoder();

function requireWebCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto?.getRandomValues) {
    throw new Error('This browser does not provide the required secure cryptography. Open VaultX using HTTPS in a modern browser.');
  }
}

function toBase64(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function fromBase64(value, expectedLength, fieldName) {
  if (typeof value !== 'string' || value.length > MAX_FILE_BYTES * 2) {
    throw new Error(`The encrypted vault has an invalid ${fieldName}.`);
  }
  let binary;
  try { binary = atob(value); } catch { throw new Error(`The encrypted vault has an invalid ${fieldName}.`); }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new Error(`The encrypted vault has an invalid ${fieldName}.`);
  }
  return bytes;
}

function validatePassword(masterPassword) {
  if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
    throw new Error('Enter your master password.');
  }
  if (encoder.encode(masterPassword).length > 1024) {
    throw new Error('The master password is too long.');
  }
}

function validateVaultData(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data) || data.schemaVersion !== 1 || !Array.isArray(data.accounts)) {
    throw new Error('The decrypted vault data has an unsupported structure.');
  }
}

function associatedData(envelope) {
  // These public fields are authenticated along with the ciphertext.
  return encoder.encode(JSON.stringify({
    format: envelope.format,
    version: envelope.version,
    kdf: envelope.kdf,
    cipher: { name: envelope.cipher.name, tagLength: envelope.cipher.tagLength }
  }));
}

function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
      envelope.format !== FORMAT || envelope.version !== VERSION ||
      !envelope.kdf || envelope.kdf.name !== 'PBKDF2' || envelope.kdf.hash !== 'SHA-256' ||
      !Number.isSafeInteger(envelope.kdf.iterations) ||
      envelope.kdf.iterations < MIN_ACCEPTED_ITERATIONS || envelope.kdf.iterations > MAX_ACCEPTED_ITERATIONS ||
      !envelope.cipher || envelope.cipher.name !== 'AES-GCM' || envelope.cipher.tagLength !== 128 ||
      typeof envelope.ciphertext !== 'string') {
    throw new Error('This is not a supported VaultX encrypted vault file.');
  }
  fromBase64(envelope.kdf.salt, 16, 'salt');
  fromBase64(envelope.cipher.iv, 12, 'encryption IV');
  const ciphertext = fromBase64(envelope.ciphertext, undefined, 'encrypted data');
  if (ciphertext.length < 16 || ciphertext.length > MAX_FILE_BYTES) {
    throw new Error('The encrypted vault file has an invalid size.');
  }
}

async function deriveKey(masterPassword, salt, iterations) {
  validatePassword(masterPassword);
  const passwordKey = await crypto.subtle.importKey(
    'raw', encoder.encode(masterPassword), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptWithEnvelope(data, key, envelope) {
  requireWebCrypto();
  validateVaultData(data);
  if (!key || key.type !== 'secret' || key.extractable !== false || key.algorithm?.name !== 'AES-GCM') {
    throw new Error('The in-memory vault key is unavailable. Unlock the vault again.');
  }
  const plaintext = encoder.encode(JSON.stringify(data));
  if (plaintext.length > MAX_FILE_BYTES - 16) throw new Error('The vault is too large to encrypt.');
  const salt = fromBase64(envelope.kdf.salt, 16, 'salt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: associatedData(envelope), tagLength: 128 },
    key,
    plaintext
  );
  return {
    format: envelope.format,
    version: envelope.version,
    kdf: { ...envelope.kdf },
    cipher: { name: 'AES-GCM', iv: toBase64(iv), tagLength: 128 },
    ciphertext: toBase64(new Uint8Array(encrypted))
  };
}

/** Create a new vault file with a fresh random 128-bit salt and IV. */
export async function createEncryptedVault(masterPassword) {
  requireWebCrypto();
  validatePassword(masterPassword);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const metadata = {
    format: FORMAT,
    version: VERSION,
    kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: KDF_ITERATIONS, salt: toBase64(salt) },
    cipher: { name: 'AES-GCM', iv: '', tagLength: 128 }
  };
  const key = await deriveKey(masterPassword, salt, KDF_ITERATIONS);
  return encryptWithEnvelope({ schemaVersion: 1, accounts: [] }, key, metadata);
}

/** Encrypt updated vault contents using the file's salt and a fresh IV. */
export async function encryptVaultData(data, key, existingEnvelope) {
  validateEnvelope(existingEnvelope);
  return encryptWithEnvelope(data, key, existingEnvelope);
}

/** Derive a non-exportable in-memory key and decrypt only after GCM authentication. */
export async function unlockVault(envelope, masterPassword) {
  requireWebCrypto();
  validatePassword(masterPassword);
  validateEnvelope(envelope);
  try {
    const salt = fromBase64(envelope.kdf.salt, 16, 'salt');
    const iv = fromBase64(envelope.cipher.iv, 12, 'encryption IV');
    const ciphertext = fromBase64(envelope.ciphertext, undefined, 'encrypted data');
    const key = await deriveKey(masterPassword, salt, envelope.kdf.iterations);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: associatedData(envelope), tagLength: 128 },
      key,
      ciphertext
    );
    const data = JSON.parse(new TextDecoder().decode(plaintext));
    validateVaultData(data);
    return { data, key };
  } catch {
    // Do not distinguish a wrong password from damaged or altered ciphertext.
    throw new Error('Could not unlock this vault. Check the master password and vault file.');
  }
}

/** Convenience decryption API for callers that do not need to update the vault. */
export async function decryptVaultData(envelope, masterPassword) {
  return (await unlockVault(envelope, masterPassword)).data;
}

/** Parse an imported file and reject malformed or oversized input early. */
export function parseVaultFile(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > MAX_FILE_BYTES) {
    throw new Error('The selected vault file is too large or unreadable.');
  }
  let envelope;
  try { envelope = JSON.parse(text); } catch { throw new Error('The selected file is not valid VaultX data.'); }
  validateEnvelope(envelope);
  return envelope;
}

/** Return a JSON string suitable for downloading as a .vaultx file. */
export function serializeVaultFile(envelope) {
  validateEnvelope(envelope);
  return `${JSON.stringify(envelope, null, 2)}\n`;
}
