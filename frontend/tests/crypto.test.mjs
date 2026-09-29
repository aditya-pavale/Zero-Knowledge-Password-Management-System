// Run with: node --test frontend/tests/
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
globalThis.hashwasm = require("../static/vendor/argon2.umd.min.js");

const c = await import("../static/js/crypto.js");

// Small Argon2 parameters keep the test fast; production uses 64 MiB / 3 iterations.
const KDF = { kdf_memory_kib: 8192, kdf_iterations: 2, kdf_parallelism: 1 };

test("argon2id + HKDF are deterministic and separate auth from encryption", async () => {
  const salt = c.b64encode(new Uint8Array(16).fill(7));
  const a = await c.deriveLoginSecrets("correct horse battery staple", salt, KDF);
  const b = await c.deriveLoginSecrets("correct horse battery staple", salt, KDF);
  const other = await c.deriveLoginSecrets("wrong password", salt, KDF);
  assert.equal(a.authHash, b.authHash);
  assert.notEqual(a.authHash, other.authHash);
  assert.equal(c.b64decode(a.authHash).length, 32);
  // encKey is non-extractable: the auth hash can't be used to recover it.
  await assert.rejects(globalThis.crypto.subtle.exportKey("raw", a.encKey));
});

test("register -> unlock -> encrypt/decrypt item round trip", async () => {
  const { payload, session } = await c.createAccount("alice", "Tr0ub4dor&3-horse-staple", KDF);
  const secrets = await c.deriveLoginSecrets("Tr0ub4dor&3-horse-staple", payload.kdf_salt, payload);
  assert.equal(secrets.authHash, payload.auth_hash);

  const unlocked = await c.unlockAccount({ ...payload }, secrets.encKey);
  const item = { title: "GitHub", username: "alice", password: "s3cret!", url: "", notes: "" };
  const record = await c.encryptItem(session.vaultKey, 1, item);
  assert.ok(!record.ciphertext.includes("s3cret"));
  assert.deepEqual(await c.decryptItem(unlocked.vaultKey, 1, record), item);

  // AAD binds the item to its owner: replaying it under another user id fails.
  await assert.rejects(c.decryptItem(unlocked.vaultKey, 2, record));
});

test("wrong master password cannot unwrap the vault key", async () => {
  const { payload } = await c.createAccount("bob", "a-very-long-master-password-1", KDF);
  const wrong = await c.deriveLoginSecrets("not-the-password-at-all-2", payload.kdf_salt, payload);
  await assert.rejects(c.unlockAccount(payload, wrong.encKey));
});

test("hybrid share: sign, verify, decrypt; tampering is rejected", async () => {
  const alice = await c.createAccount("alice", "alice-master-password-123", KDF);
  const bob = await c.createAccount("bob", "bob-master-password-456", KDF);
  const item = { title: "Wifi", username: "", password: "hunter2hunter2", url: "", notes: "" };

  const share = await c.createShare({
    sender: "alice",
    recipient: "bob",
    recipientEncryptionPublicKey: bob.payload.encryption_public_key,
    signingPrivateKey: alice.session.signingPrivateKey,
    item,
  });
  const received = { ...share, sender: "alice", sender_signing_public_key: alice.payload.signing_public_key };
  assert.deepEqual(await c.openShare(received, bob.session.encryptionPrivateKey), item);

  // Flip one ciphertext byte -> signature no longer verifies.
  const bytes = c.b64decode(share.ciphertext);
  bytes[0] ^= 1;
  await assert.rejects(
    c.openShare({ ...received, ciphertext: c.b64encode(bytes) }, bob.session.encryptionPrivateKey),
    /Signature verification failed/
  );
  // Signed by someone else (bob's signing key presented as alice's) -> rejected.
  await assert.rejects(
    c.openShare({ ...received, sender_signing_public_key: bob.payload.signing_public_key },
      bob.session.encryptionPrivateKey),
    /Signature verification failed/
  );
  // Alice can't read what she sent to bob (only bob's private key unwraps K).
  await assert.rejects(c.openShare(received, alice.session.encryptionPrivateKey));
});

test("master password change keeps the same vault key", async () => {
  const { payload, session } = await c.createAccount("carol", "first-master-password-1!", KDF);
  const record = await c.encryptItem(session.vaultKey, 5, { title: "x", password: "y" });
  const change = await c.rewrapVaultKey(payload, "first-master-password-1!", "second-master-password-2?", KDF);
  const next = await c.deriveLoginSecrets("second-master-password-2?", change.kdf_salt, change);
  assert.equal(next.authHash, change.new_auth_hash);
  const unlocked = await c.unlockAccount({ ...payload, ...change }, next.encKey);
  assert.deepEqual(await c.decryptItem(unlocked.vaultKey, 5, record), { title: "x", password: "y" });
});

test("password generator honours length and character sets", () => {
  for (let i = 0; i < 50; i++) {
    const p = c.generatePassword(16, ["lower", "digits"]);
    assert.equal(p.length, 16);
    assert.match(p, /^[a-z0-9]+$/);
    assert.match(p, /[0-9]/);
  }
  assert.ok(c.masterPasswordProblems("short", "x").length > 0);
  assert.deepEqual(c.masterPasswordProblems("Gl4ss-Orbit-Pepper-Canyon!", "dave"), []);
});
