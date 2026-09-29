// Client-side cryptography for the zero-knowledge vault.
//
// Key hierarchy
//   master password --Argon2id(salt, params)--> master key (32 bytes, never leaves the browser)
//   master key --HKDF-SHA256("vault-auth-v1")--> auth hash   (sent to server as the login secret)
//   master key --HKDF-SHA256("vault-enc-v1")---> enc key     (wraps the vault key)
//   vault key (random 256-bit) --AES-256-GCM--> items, RSA private keys
//
// Sharing (hybrid): random AES key K encrypts the item; RSA-OAEP(recipient) wraps K;
// the sender signs everything with RSA-PSS.
//
// Works in browsers and in Node >= 20 (globalThis.crypto.subtle). Argon2id comes from
// the vendored hash-wasm build, exposed as globalThis.hashwasm.

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const RSA_BITS = 3072;
export const PSS_SALT_LENGTH = 32;
const RSA_OAEP = { name: "RSA-OAEP", hash: "SHA-256" };
const RSA_PSS = { name: "RSA-PSS", hash: "SHA-256" };

// ---------------------------------------------------------------- encoding helpers

export function b64encode(bytes) {
  bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function b64decode(str) {
  const binary = atob(str);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

const utf8 = (s) => encoder.encode(s);

// ---------------------------------------------------------------- key derivation

export async function deriveMasterKey(password, saltB64, params) {
  if (!globalThis.hashwasm || !globalThis.hashwasm.argon2id) {
    throw new Error("Argon2id implementation not loaded");
  }
  return globalThis.hashwasm.argon2id({
    password: utf8(password.normalize("NFKC")),
    salt: b64decode(saltB64),
    parallelism: params.kdf_parallelism,
    iterations: params.kdf_iterations,
    memorySize: params.kdf_memory_kib,
    hashLength: 32,
    outputType: "binary",
  });
}

async function hkdf(masterKeyBytes, info) {
  const base = await subtle.importKey("raw", masterKeyBytes, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: utf8(info) }, base, 256)
  );
}

// Returns the value sent to the server and the key that wraps the vault key.
export async function deriveLoginSecrets(password, saltB64, params) {
  const master = await deriveMasterKey(password, saltB64, params);
  try {
    const authHash = b64encode(await hkdf(master, "vault-auth-v1"));
    const encKeyBytes = await hkdf(master, "vault-enc-v1");
    const encKey = await subtle.importKey("raw", encKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]);
    encKeyBytes.fill(0);
    return { authHash, encKey };
  } finally {
    master.fill(0);
  }
}

// ---------------------------------------------------------------- AES-256-GCM

export async function aesEncrypt(key, plaintext, aad) {
  const iv = randomBytes(12);
  const params = { name: "AES-GCM", iv };
  if (aad) params.additionalData = utf8(aad);
  const ct = await subtle.encrypt(params, key, plaintext);
  return { iv: b64encode(iv), ciphertext: b64encode(ct) };
}

export async function aesDecrypt(key, ivB64, ciphertextB64, aad) {
  const params = { name: "AES-GCM", iv: b64decode(ivB64) };
  if (aad) params.additionalData = utf8(aad);
  try {
    return new Uint8Array(await subtle.decrypt(params, key, b64decode(ciphertextB64)));
  } catch {
    throw new Error("Decryption failed: wrong key or tampered data");
  }
}

// "v1.<iv>.<ciphertext>" - used for wrapped keys stored on the user record.
export async function seal(key, bytes, aad) {
  const { iv, ciphertext } = await aesEncrypt(key, bytes, aad);
  return `v1.${iv}.${ciphertext}`;
}

export async function open(key, envelope, aad) {
  const parts = envelope.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") throw new Error("Unknown envelope format");
  return aesDecrypt(key, parts[1], parts[2], aad);
}

const aad = {
  vaultKey: (username) => `vault-key-v1:${username}`,
  oaepPriv: (username) => `rsa-oaep-priv-v1:${username}`,
  pssPriv: (username) => `rsa-pss-priv-v1:${username}`,
  item: (userId) => `vault-item-v1:${userId}`,
  share: (sender, recipient) => `vault-share-v1:${sender}|${recipient}`,
};

async function importVaultKey(raw) {
  return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

// ---------------------------------------------------------------- account setup / unlock

async function generateRsa(algorithm, usages) {
  return subtle.generateKey(
    { ...algorithm, modulusLength: RSA_BITS, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    usages
  );
}

// Everything the server needs for registration, plus the unlocked session keys.
export async function createAccount(username, password, kdfParams) {
  const kdf_salt = b64encode(randomBytes(16));
  const params = { ...kdfParams, kdf_salt };
  const { authHash, encKey } = await deriveLoginSecrets(password, kdf_salt, params);

  const vaultKeyRaw = randomBytes(32);
  const protected_vault_key = await seal(encKey, vaultKeyRaw, aad.vaultKey(username));
  const vaultKey = await importVaultKey(vaultKeyRaw);
  vaultKeyRaw.fill(0);

  const [oaep, pss] = await Promise.all([
    generateRsa(RSA_OAEP, ["encrypt", "decrypt"]),
    generateRsa(RSA_PSS, ["sign", "verify"]),
  ]);
  const oaepPkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", oaep.privateKey));
  const pssPkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", pss.privateKey));
  const payload = {
    username,
    auth_hash: authHash,
    kdf_salt,
    kdf_memory_kib: params.kdf_memory_kib,
    kdf_iterations: params.kdf_iterations,
    kdf_parallelism: params.kdf_parallelism,
    protected_vault_key,
    encryption_public_key: b64encode(await subtle.exportKey("spki", oaep.publicKey)),
    encrypted_encryption_private_key: await seal(vaultKey, oaepPkcs8, aad.oaepPriv(username)),
    signing_public_key: b64encode(await subtle.exportKey("spki", pss.publicKey)),
    encrypted_signing_private_key: await seal(vaultKey, pssPkcs8, aad.pssPriv(username)),
  };
  // Re-import private keys as non-extractable for this session.
  const session = {
    vaultKey,
    encryptionPrivateKey: await subtle.importKey("pkcs8", oaepPkcs8, RSA_OAEP, false, ["decrypt"]),
    signingPrivateKey: await subtle.importKey("pkcs8", pssPkcs8, RSA_PSS, false, ["sign"]),
  };
  oaepPkcs8.fill(0);
  pssPkcs8.fill(0);
  return { payload, session };
}

// Unwrap the vault key and RSA private keys from the profile returned at login.
export async function unlockAccount(profile, encKey) {
  const vaultKeyRaw = await open(encKey, profile.protected_vault_key, aad.vaultKey(profile.username));
  const vaultKey = await importVaultKey(vaultKeyRaw);
  vaultKeyRaw.fill(0);
  const oaepPkcs8 = await open(vaultKey, profile.encrypted_encryption_private_key, aad.oaepPriv(profile.username));
  const pssPkcs8 = await open(vaultKey, profile.encrypted_signing_private_key, aad.pssPriv(profile.username));
  const session = {
    vaultKey,
    encryptionPrivateKey: await subtle.importKey("pkcs8", oaepPkcs8, RSA_OAEP, false, ["decrypt"]),
    signingPrivateKey: await subtle.importKey("pkcs8", pssPkcs8, RSA_PSS, false, ["sign"]),
  };
  oaepPkcs8.fill(0);
  pssPkcs8.fill(0);
  return session;
}

// Re-wrap the same vault key under a new master password.
export async function rewrapVaultKey(profile, currentPassword, newPassword, kdfParams) {
  const current = await deriveLoginSecrets(currentPassword, profile.kdf_salt, profile);
  const vaultKeyRaw = await open(current.encKey, profile.protected_vault_key, aad.vaultKey(profile.username));
  const kdf_salt = b64encode(randomBytes(16));
  const params = { ...kdfParams, kdf_salt };
  const next = await deriveLoginSecrets(newPassword, kdf_salt, params);
  const protected_vault_key = await seal(next.encKey, vaultKeyRaw, aad.vaultKey(profile.username));
  vaultKeyRaw.fill(0);
  return {
    current_auth_hash: current.authHash,
    new_auth_hash: next.authHash,
    kdf_salt,
    kdf_memory_kib: params.kdf_memory_kib,
    kdf_iterations: params.kdf_iterations,
    kdf_parallelism: params.kdf_parallelism,
    protected_vault_key,
  };
}

// ---------------------------------------------------------------- vault items

export async function encryptItem(vaultKey, userId, item) {
  return aesEncrypt(vaultKey, utf8(JSON.stringify(item)), aad.item(userId));
}

export async function decryptItem(vaultKey, userId, record) {
  const bytes = await aesDecrypt(vaultKey, record.iv, record.ciphertext, aad.item(userId));
  return JSON.parse(decoder.decode(bytes));
}

// ---------------------------------------------------------------- sharing + signatures

// Must match vault_project/cryptoutils.py:share_signing_message
export function shareSigningMessage({ sender, recipient, iv, ciphertext, wrapped_key }) {
  return utf8(["vault-share-v1", sender, recipient, iv, ciphertext, wrapped_key].join("|"));
}

export async function createShare({ sender, recipient, recipientEncryptionPublicKey, signingPrivateKey, item }) {
  const k = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const { iv, ciphertext } = await aesEncrypt(k, utf8(JSON.stringify(item)), aad.share(sender, recipient));
  const recipientKey = await subtle.importKey(
    "spki", b64decode(recipientEncryptionPublicKey), RSA_OAEP, false, ["encrypt"]
  );
  const kRaw = new Uint8Array(await subtle.exportKey("raw", k));
  const wrapped_key = b64encode(await subtle.encrypt({ name: "RSA-OAEP" }, recipientKey, kRaw));
  kRaw.fill(0);
  const message = shareSigningMessage({ sender, recipient, iv, ciphertext, wrapped_key });
  const signature = b64encode(
    await subtle.sign({ name: "RSA-PSS", saltLength: PSS_SALT_LENGTH }, signingPrivateKey, message)
  );
  return { recipient, iv, ciphertext, wrapped_key, signature };
}

export async function verifyShare(share) {
  const key = await subtle.importKey("spki", b64decode(share.sender_signing_public_key), RSA_PSS, false, ["verify"]);
  return subtle.verify(
    { name: "RSA-PSS", saltLength: PSS_SALT_LENGTH },
    key,
    b64decode(share.signature),
    shareSigningMessage(share)
  );
}

// Verify first; refuse to decrypt anything whose signature doesn't check out.
export async function openShare(share, encryptionPrivateKey) {
  if (!(await verifyShare(share))) throw new Error("Signature verification failed");
  const kRaw = new Uint8Array(
    await subtle.decrypt({ name: "RSA-OAEP" }, encryptionPrivateKey, b64decode(share.wrapped_key))
  );
  const k = await subtle.importKey("raw", kRaw, "AES-GCM", false, ["decrypt"]);
  kRaw.fill(0);
  const bytes = await aesDecrypt(k, share.iv, share.ciphertext, aad.share(share.sender, share.recipient));
  return JSON.parse(decoder.decode(bytes));
}

// Same format as vault_project/cryptoutils.py:fingerprint
export async function fingerprint(publicKeyB64) {
  const digest = new Uint8Array(await subtle.digest("SHA-256", b64decode(publicKeyB64)));
  const hex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
  return hex.match(/.{4}/g).join(":");
}

// ---------------------------------------------------------------- passwords

const CHARSETS = {
  lower: "abcdefghijkmnopqrstuvwxyz",
  upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",
  digits: "23456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?",
};

function randomIndex(n) {
  // Rejection sampling to avoid modulo bias.
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do globalThis.crypto.getRandomValues(buf);
  while (buf[0] >= limit);
  return buf[0] % n;
}

export function generatePassword(length = 20, sets = ["lower", "upper", "digits", "symbols"]) {
  const pools = sets.map((s) => CHARSETS[s]).filter(Boolean);
  if (!pools.length) throw new Error("Pick at least one character set");
  const all = pools.join("");
  const chars = pools.map((p) => p[randomIndex(p.length)]); // at least one from each set
  while (chars.length < length) chars.push(all[randomIndex(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

// Rough entropy estimate in bits (pool size ^ length); good enough for a strength meter.
export function estimateEntropy(password) {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;
  const unique = new Set(password).size;
  return Math.round(Math.min(password.length, unique * 1.5) * Math.log2(Math.max(pool, 1)));
}

export function masterPasswordProblems(password, username) {
  const problems = [];
  if (password.length < 12) problems.push("Use at least 12 characters.");
  if (estimateEntropy(password) < 60) problems.push("Add more length or variety (aim for 60+ bits).");
  if (username && password.toLowerCase().includes(username.toLowerCase())) {
    problems.push("Don't include your username.");
  }
  return problems;
}
