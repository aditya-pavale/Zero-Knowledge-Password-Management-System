// End-to-end smoke test: drives a running server with the *browser's* crypto.js.
// Proves JS-produced ciphertext/signatures interoperate with the Python server.
//
//   node scripts/e2e_smoke.mjs http://127.0.0.1:8000
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
globalThis.hashwasm = require("../frontend/static/vendor/argon2.umd.min.js");
const c = await import("../frontend/static/js/crypto.js");

const BASE = process.argv[2] || "http://127.0.0.1:8000";
const run = Date.now().toString(36);

async function call(method, path, body, token) {
  const res = await fetch(BASE + path, {
    method,
    headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${text}`);
  return data;
}

async function registerAndLogin(username, password) {
  const kdf = await call("GET", "/api/auth/kdf-defaults/");
  const { payload } = await c.createAccount(username, password, kdf);
  await call("POST", "/api/auth/register/", payload);
  // Fresh login exactly like the UI does.
  const params = await call("POST", "/api/auth/prelogin/", { username });
  const { authHash, encKey } = await c.deriveLoginSecrets(password, params.kdf_salt, params);
  const { user, tokens } = await call("POST", "/api/auth/login/", { username, auth_hash: authHash });
  const keys = await c.unlockAccount(user, encKey);
  return { user, tokens, keys };
}

const alice = await registerAndLogin(`alice_${run}`, "alice-e2e-master-password-1!");
const bob = await registerAndLogin(`bob_${run}`, "bob-e2e-master-password-2?");
console.log("registered + logged in:", alice.user.username, bob.user.username);

const item = { title: "E2E secret", username: "a", password: "pa55-w0rd-e2e", url: "https://example.com", notes: "" };
const created = await call("POST", "/api/vault/items/", await c.encryptItem(alice.keys.vaultKey, alice.user.id, item), alice.tokens.access);
const fetched = await call("GET", `/api/vault/items/${created.id}/`, null, alice.tokens.access);
assert.deepEqual(await c.decryptItem(alice.keys.vaultKey, alice.user.id, fetched), item);
assert.ok(!JSON.stringify(fetched).includes("pa55"));
console.log("vault item: encrypted in JS, stored, fetched, decrypted ✓");

const keys = await call("GET", `/api/auth/users/${bob.user.username}/public-keys/`, null, alice.tokens.access);
assert.equal(await c.fingerprint(keys.encryption_public_key), keys.encryption_key_fingerprint);
const share = await c.createShare({
  sender: alice.user.username,
  recipient: bob.user.username,
  recipientEncryptionPublicKey: keys.encryption_public_key,
  signingPrivateKey: alice.keys.signingPrivateKey,
  item,
});
await call("POST", "/api/shares/", share, alice.tokens.access); // server verifies the RSA-PSS signature in Python
console.log("share: JS RSA-PSS signature accepted by Python server ✓");

const inbox = await call("GET", "/api/shares/inbox/", null, bob.tokens.access);
assert.deepEqual(await c.openShare(inbox.results[0], bob.keys.encryptionPrivateKey), item);
console.log("share: bob verified signature + unwrapped RSA-OAEP key + decrypted ✓");

console.log("E2E OK");
