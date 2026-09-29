// Single-page UI. All plaintext and keys live only in this module's memory and are
// wiped on logout, lock, or after inactivity. User data is only ever rendered with
// textContent (see h()), never innerHTML.

import { api, ApiError, clearTokens, getAll, getRefreshToken, onExpired, setTokens } from "./api.js";
import * as vc from "./crypto.js";

const AUTO_LOCK_MS = 10 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 30 * 1000;

const state = {
  profile: null, // server profile (public data + wrapped keys)
  keys: null, // { vaultKey, encryptionPrivateKey, signingPrivateKey }
  items: [], // [{ record, data }]
  view: "vault",
};

// ------------------------------------------------------------------ DOM helpers

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, String(v));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

const $ = (sel) => document.querySelector(sel);
const app = () => $("#app");

function toast(message, kind = "info") {
  const el = $("#toast");
  el.textContent = message;
  el.className = `toast ${kind}`;
  el.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (el.hidden = true), 4000);
}

function errorMessage(err) {
  if (err instanceof ApiError) return err.message;
  return err && err.message ? err.message : String(err);
}

async function busy(button, label, fn) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try {
    return await fn();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function openModal(title, body, actions = []) {
  const modal = $("#modal");
  modal.replaceChildren(
    h("form", { method: "dialog", class: "modal-body" },
      h("h2", {}, title),
      body,
      h("div", { class: "actions" },
        ...actions,
        h("button", { type: "submit", class: "secondary", value: "cancel" }, "Close")))
  );
  modal.showModal();
  return modal;
}

function closeModal() {
  const modal = $("#modal");
  if (modal.open) modal.close();
}

function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString() : "";
}

// ------------------------------------------------------------------ session lifecycle

function wipeSession() {
  state.profile = null;
  state.keys = null;
  state.items = [];
  clearTokens();
  closeModal();
}

async function logout(reason) {
  const refresh = getRefreshToken();
  if (refresh) {
    try {
      await api.post("/api/auth/logout/", { refresh });
    } catch {
      /* token may already be expired; local wipe below is what matters */
    }
  }
  wipeSession();
  renderAuth();
  if (reason) toast(reason);
}

onExpired(() => {
  wipeSession();
  renderAuth();
  toast("Session expired. Please unlock again.", "warn");
});

let idleTimer;
function resetIdle() {
  clearTimeout(idleTimer);
  if (state.keys) idleTimer = setTimeout(() => logout("Vault locked after inactivity."), AUTO_LOCK_MS);
}
["click", "keydown", "mousemove", "touchstart"].forEach((evt) =>
  document.addEventListener(evt, resetIdle, { passive: true })
);

async function startSession(user, tokens, keys) {
  setTokens(tokens);
  state.profile = user;
  state.keys = keys;
  state.view = "vault";
  resetIdle();
  await loadItems();
  render();
}

// ------------------------------------------------------------------ auth screens

function renderAuth(mode = "login") {
  $("#nav").hidden = true;
  $("#whoami").hidden = true;
  const username = h("input", { name: "username", autocomplete: "username", required: true, minlength: 3, maxlength: 64, pattern: "[A-Za-z0-9_.\\-]+" });
  const password = h("input", { name: "password", type: "password", autocomplete: mode === "login" ? "current-password" : "new-password", required: true });
  const confirm = h("input", { name: "confirm", type: "password", autocomplete: "new-password", required: true });
  const meter = h("div", { class: "meter" });
  const status = h("p", { class: "muted small" });
  const submit = h("button", { type: "submit" }, mode === "login" ? "Unlock vault" : "Create account");

  if (mode === "register") {
    password.addEventListener("input", () => {
      const bits = vc.estimateEntropy(password.value);
      const problems = vc.masterPasswordProblems(password.value, username.value);
      const bar = h("div", { class: `bar ${bits >= 80 ? "good" : bits >= 60 ? "ok" : "weak"}` });
      bar.style.width = `${Math.min(100, bits)}%`; // CSSOM, allowed under the strict CSP
      meter.replaceChildren(
        bar,
        h("span", { class: "small" }, `${bits} bits${problems.length ? " - " + problems[0] : ""}`)
      );
    });
  }

  const form = h("form", { class: "card auth", onsubmit: async (e) => {
    e.preventDefault();
    await busy(submit, "Deriving key (Argon2id)...", async () => {
      try {
        if (mode === "login") await doLogin(username.value.trim(), password.value, status);
        else await doRegister(username.value.trim(), password.value, confirm.value, status);
      } catch (err) {
        status.textContent = "";
        toast(errorMessage(err), "error");
      } finally {
        password.value = "";
        confirm.value = "";
      }
    });
  } },
    h("h1", {}, mode === "login" ? "Unlock your vault" : "Create your vault"),
    h("label", {}, "Username", username),
    h("label", {}, "Master password", password),
    mode === "register" ? meter : null,
    mode === "register" ? h("label", {}, "Confirm master password", confirm) : null,
    mode === "register"
      ? h("p", { class: "notice" }, "Your master password never leaves this browser and cannot be recovered. If you forget it, your vault is lost.")
      : null,
    submit,
    status,
    h("p", { class: "small" },
      mode === "login" ? "No account yet? " : "Already registered? ",
      h("a", { href: "#", onclick: (e) => { e.preventDefault(); renderAuth(mode === "login" ? "register" : "login"); } },
        mode === "login" ? "Create one" : "Log in"))
  );
  app().replaceChildren(
    h("section", { class: "auth-wrap" }, form, explainer())
  );
  username.focus();
}

function explainer() {
  return h("aside", { class: "card explainer" },
    h("h2", {}, "How your data is protected"),
    h("ol", {},
      h("li", {}, "Argon2id stretches your master password into a key, in your browser."),
      h("li", {}, "HKDF splits it: one half proves who you are, the other unlocks your vault key."),
      h("li", {}, "Every entry is encrypted with AES-256-GCM before it is uploaded."),
      h("li", {}, "The server stores only ciphertext. It can't read your passwords."),
      h("li", {}, "Sharing uses RSA-OAEP to wrap a one-time key, and RSA-PSS signatures prove who sent it.")));
}

async function doLogin(username, password, status) {
  status.textContent = "Fetching key-derivation parameters...";
  const params = await api.post("/api/auth/prelogin/", { username });
  status.textContent = `Running Argon2id (${params.kdf_memory_kib / 1024} MiB, ${params.kdf_iterations} passes)...`;
  const { authHash, encKey } = await vc.deriveLoginSecrets(password, params.kdf_salt, params);
  status.textContent = "Authenticating...";
  const { user, tokens } = await api.post("/api/auth/login/", { username, auth_hash: authHash });
  status.textContent = "Decrypting vault key...";
  const keys = await vc.unlockAccount(user, encKey);
  await startSession(user, tokens, keys);
}

async function doRegister(username, password, confirm, status) {
  if (password !== confirm) throw new Error("Passwords don't match.");
  const problems = vc.masterPasswordProblems(password, username);
  if (problems.length) throw new Error(problems.join(" "));
  const defaults = await api.get("/api/auth/kdf-defaults/");
  status.textContent = "Deriving keys and generating RSA-3072 key pairs (this takes a few seconds)...";
  const { payload, session } = await vc.createAccount(username, password, defaults);
  status.textContent = "Registering...";
  const { user, tokens } = await api.post("/api/auth/register/", payload);
  await startSession(user, tokens, session);
  toast("Vault created.", "success");
}

// ------------------------------------------------------------------ main layout

const VIEWS = [
  { id: "vault", label: "Vault" },
  { id: "sharing", label: "Sharing" },
  { id: "activity", label: "My activity" },
  { id: "settings", label: "Settings" },
  { id: "audit", label: "Audit log", role: "auditor" },
  { id: "users", label: "Users", role: "admin" },
  { id: "analyzer", label: "AI analyzer", role: "admin" },
];

function allowed(view) {
  const role = state.profile.role;
  if (view.role === "admin") return role === "admin";
  if (view.role === "auditor") return role === "admin" || role === "auditor";
  return true;
}

function render() {
  if (!state.keys) return renderAuth();
  const nav = $("#nav");
  nav.hidden = false;
  nav.replaceChildren(
    ...VIEWS.filter(allowed).map((v) =>
      h("button", { class: v.id === state.view ? "tab active" : "tab", onclick: () => { state.view = v.id; render(); } }, v.label))
  );
  const who = $("#whoami");
  who.hidden = false;
  who.replaceChildren(
    h("span", {}, state.profile.username),
    h("span", { class: `badge role-${state.profile.role}` }, state.profile.role),
    h("button", { class: "secondary small", onclick: () => logout("Vault locked.") }, "Lock")
  );
  const renderers = { vault: renderVault, sharing: renderSharing, activity: renderActivity, settings: renderSettings, audit: renderAudit, users: renderUsers, analyzer: renderAnalyzer };
  app().replaceChildren(h("p", { class: "muted" }, "Loading..."));
  renderers[state.view]().catch((err) => {
    app().replaceChildren(h("p", { class: "error" }, errorMessage(err)));
  });
}

// ------------------------------------------------------------------ vault

async function loadItems() {
  const records = await getAll("/api/vault/items/");
  const out = [];
  for (const record of records) {
    try {
      out.push({ record, data: await vc.decryptItem(state.keys.vaultKey, state.profile.id, record) });
    } catch {
      out.push({ record, data: null }); // tampered or undecryptable
    }
  }
  state.items = out;
}

async function copyToClipboard(text, label) {
  if (!navigator.clipboard || !window.isSecureContext) {
    return toast("Clipboard needs HTTPS (or localhost). Use Show instead.", "warn");
  }
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return toast("Clipboard access was blocked by the browser.", "error");
  }
  toast(`${label} copied. Clipboard clears in 30 s.`, "success");
  setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText("");
    } catch {
      /* readText may be denied; best effort */
    }
  }, CLIPBOARD_CLEAR_MS);
}

async function renderVault() {
  const search = h("input", { type: "search", placeholder: "Search titles, usernames, URLs...", class: "grow" });
  const list = h("div", { class: "grid" });

  const draw = () => {
    const q = search.value.toLowerCase();
    const matches = state.items.filter(({ data }) =>
      !q || (data && [data.title, data.username, data.url].some((f) => (f || "").toLowerCase().includes(q))));
    list.replaceChildren(
      ...(matches.length ? matches.map(itemCard) : [h("p", { class: "muted" }, state.items.length ? "No matches." : "Your vault is empty. Add your first password.")])
    );
  };
  search.addEventListener("input", draw);
  draw();

  app().replaceChildren(
    h("div", { class: "toolbar" },
      search,
      h("button", { onclick: () => editItem(null) }, "+ Add password"),
      h("button", { class: "secondary", onclick: async () => { await loadItems(); draw(); } }, "Refresh")),
    h("p", { class: "muted small" }, `${state.items.length} item(s). Decrypted locally; the server only holds ciphertext.`),
    list
  );
}

function itemCard({ record, data }) {
  if (!data) {
    return h("article", { class: "card item broken" },
      h("h3", {}, `Item #${record.id}`),
      h("p", { class: "error small" }, "Could not decrypt: data was tampered with or belongs to another key."),
      h("button", { class: "danger small", onclick: () => deleteItem(record) }, "Delete"));
  }
  const pw = h("code", { class: "secret" }, "••••••••••");
  let shown = false;
  return h("article", { class: "card item" },
    h("h3", {}, data.title || "(untitled)"),
    data.username ? h("p", { class: "small" }, h("span", { class: "muted" }, "User: "), data.username) : null,
    data.url ? h("p", { class: "small" }, h("span", { class: "muted" }, "URL: "), safeLink(data.url)) : null,
    h("p", {}, pw),
    data.notes ? h("p", { class: "small notes" }, data.notes) : null,
    h("div", { class: "actions wrap" },
      h("button", { class: "small", onclick: () => copyToClipboard(data.password || "", "Password") }, "Copy"),
      h("button", { class: "small secondary", onclick: () => { shown = !shown; pw.textContent = shown ? data.password : "••••••••••"; } }, "Show"),
      h("button", { class: "small secondary", onclick: () => editItem({ record, data }) }, "Edit"),
      h("button", { class: "small secondary", onclick: () => shareItem(data) }, "Share"),
      h("button", { class: "small danger", onclick: () => deleteItem(record) }, "Delete")),
    h("p", { class: "muted tiny" }, `v${record.version} · updated ${fmtDate(record.updated_at)}`));
}

function safeLink(url) {
  try {
    const parsed = new URL(url.includes("://") ? url : `https://${url}`);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      return h("a", { href: parsed.href, target: "_blank", rel: "noopener noreferrer" }, url);
    }
  } catch {
    /* fall through */
  }
  return h("span", {}, url);
}

function editItem(existing) {
  const d = existing ? existing.data : { title: "", username: "", password: "", url: "", notes: "" };
  const f = {
    title: h("input", { value: d.title, required: true, maxlength: 200 }),
    username: h("input", { value: d.username || "", autocomplete: "off" }),
    password: h("input", { value: d.password || "", type: "password", autocomplete: "new-password" }),
    url: h("input", { value: d.url || "", type: "text", placeholder: "https://..." }),
    notes: h("textarea", { rows: 3 }, d.notes || ""),
  };
  const length = h("input", { type: "number", min: 8, max: 128, value: 20, class: "narrow" });
  const symbols = h("input", { type: "checkbox", checked: true });
  const bits = h("span", { class: "small muted" });
  const updateBits = () => (bits.textContent = `${vc.estimateEntropy(f.password.value)} bits`);
  f.password.addEventListener("input", updateBits);
  updateBits();

  const save = h("button", { type: "button" }, existing ? "Save changes" : "Add to vault");
  save.addEventListener("click", () => busy(save, "Encrypting...", async () => {
    if (!f.title.value.trim()) return toast("Title is required.", "warn");
    const item = {
      title: f.title.value.trim(), username: f.username.value, password: f.password.value,
      url: f.url.value.trim(), notes: f.notes.value,
    };
    try {
      const body = await vc.encryptItem(state.keys.vaultKey, state.profile.id, item);
      if (existing) await api.put(`/api/vault/items/${existing.record.id}/`, body);
      else await api.post("/api/vault/items/", body);
      closeModal();
      await loadItems();
      render();
      toast("Saved (encrypted).", "success");
    } catch (err) {
      toast(errorMessage(err), "error");
    }
  }));

  openModal(existing ? "Edit password" : "Add password",
    h("div", { class: "form" },
      h("label", {}, "Title", f.title),
      h("label", {}, "Username", f.username),
      h("label", {}, "Password",
        h("div", { class: "row" }, f.password,
          h("button", { type: "button", class: "secondary small", onclick: () => { f.password.type = f.password.type === "password" ? "text" : "password"; } }, "Show"))),
      h("div", { class: "row small" }, "Generate: length ", length, h("label", { class: "inline" }, symbols, " symbols"),
        h("button", { type: "button", class: "secondary small", onclick: () => {
          const sets = ["lower", "upper", "digits"].concat(symbols.checked ? ["symbols"] : []);
          f.password.value = vc.generatePassword(Math.max(8, Math.min(128, Number(length.value) || 20)), sets);
          f.password.type = "text";
          updateBits();
        } }, "Generate"), bits),
      h("label", {}, "URL", f.url),
      h("label", {}, "Notes", f.notes)),
    [save]);
}

async function deleteItem(record) {
  if (!confirm("Delete this item permanently?")) return;
  try {
    await api.del(`/api/vault/items/${record.id}/`);
    await loadItems();
    render();
    toast("Deleted.");
  } catch (err) {
    toast(errorMessage(err), "error");
  }
}

// ------------------------------------------------------------------ sharing

function shareItem(data) {
  const recipient = h("input", { placeholder: "recipient username", required: true });
  const info = h("div", { class: "small" });
  let keys = null;
  const lookup = h("button", { type: "button", class: "secondary" }, "Look up keys");
  const send = h("button", { type: "button", disabled: true }, "Encrypt, sign & send");

  lookup.addEventListener("click", () => busy(lookup, "Looking up...", async () => {
    try {
      keys = await api.get(`/api/auth/users/${encodeURIComponent(recipient.value.trim())}/public-keys/`);
      const fp = await vc.fingerprint(keys.encryption_public_key);
      if (fp !== keys.encryption_key_fingerprint) throw new Error("Fingerprint mismatch");
      info.replaceChildren(
        h("p", {}, "Recipient: ", h("strong", {}, keys.username)),
        h("p", {}, "Encryption key fingerprint:"),
        h("code", { class: "fp" }, fp),
        h("p", { class: "notice" }, "Compare this fingerprint with the recipient over another channel (in person, phone) before sending. It stops a malicious server from swapping in its own key."));
      send.disabled = false;
    } catch (err) {
      keys = null;
      send.disabled = true;
      info.replaceChildren(h("p", { class: "error" }, errorMessage(err)));
    }
  }));

  send.addEventListener("click", () => busy(send, "Encrypting...", async () => {
    try {
      const payload = await vc.createShare({
        sender: state.profile.username,
        recipient: keys.username,
        recipientEncryptionPublicKey: keys.encryption_public_key,
        signingPrivateKey: state.keys.signingPrivateKey,
        item: data,
      });
      await api.post("/api/shares/", payload);
      closeModal();
      toast(`Shared "${data.title}" with ${keys.username}.`, "success");
    } catch (err) {
      toast(errorMessage(err), "error");
    }
  }));

  openModal(`Share "${data.title}"`,
    h("div", { class: "form" },
      h("p", { class: "small muted" }, "A one-time AES-256 key encrypts this entry. It's wrapped with the recipient's RSA-OAEP public key and the whole package is signed with your RSA-PSS key."),
      h("div", { class: "row" }, recipient, lookup),
      info),
    [send]);
}

async function removeShare(id) {
  try {
    await api.del(`/api/shares/${id}/`);
    render();
  } catch (err) {
    toast(errorMessage(err), "error");
  }
}

async function renderSharing() {
  const [inbox, outbox] = await Promise.all([getAll("/api/shares/inbox/"), getAll("/api/shares/outbox/")]);
  const inboxRows = await Promise.all(inbox.map(async (share) => {
    let item = null;
    let status;
    try {
      item = await vc.openShare(share, state.keys.encryptionPrivateKey);
      status = h("span", { class: "badge ok" }, "✓ signature verified");
    } catch (err) {
      status = h("span", { class: "badge bad" }, `✗ ${errorMessage(err)}`);
    }
    return h("article", { class: "card item" },
      h("h3", {}, item ? item.title : "(unreadable share)"),
      h("p", { class: "small" }, "From ", h("strong", {}, share.sender), ` · ${fmtDate(share.created_at)} · ${share.status}`),
      h("p", {}, status),
      h("p", { class: "tiny muted" }, "Sender signing key: ", h("code", {}, share.sender_signing_key_fingerprint)),
      h("div", { class: "actions wrap" },
        item ? h("button", { class: "small", onclick: (e) => busy(e.target, "Saving...", async () => {
          try {
            await api.post("/api/vault/items/", await vc.encryptItem(state.keys.vaultKey, state.profile.id, item));
            await api.post(`/api/shares/${share.id}/accept/`);
            await loadItems();
            toast("Saved to your vault (re-encrypted with your key).", "success");
            render();
          } catch (err) {
            toast(errorMessage(err), "error");
          }
        }) }, share.status === "accepted" ? "Save again" : "Save to my vault") : null,
        h("button", { class: "small danger", onclick: () => removeShare(share.id) }, "Dismiss")));
  }));

  app().replaceChildren(
    h("h2", {}, "Inbox"),
    h("div", { class: "grid" }, inboxRows.length ? inboxRows : h("p", { class: "muted" }, "Nothing shared with you yet.")),
    h("h2", {}, "Sent"),
    outbox.length
      ? table(["Recipient", "Status", "Sent", ""], outbox.map((s) => [
        s.recipient, s.status, fmtDate(s.created_at),
        h("button", { class: "small danger", onclick: () => removeShare(s.id) },
          s.status === "pending" ? "Revoke" : "Remove"),
      ]))
      : h("p", { class: "muted" }, "You haven't shared anything."),
    h("p", { class: "small muted" }, "Tip: share from the Vault tab using the Share button on an entry."));
}

// ------------------------------------------------------------------ tables / logs

function table(headers, rows) {
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, ...headers.map((x) => h("th", {}, x)))),
      h("tbody", {}, ...rows.map((r) => h("tr", {}, ...r.map((c) => h("td", {}, c)))))));
}

function logRows(logs) {
  return logs.map((l) => [
    fmtDate(l.timestamp), l.actor_username || "-",
    h("span", { class: `badge ${l.success ? "" : "bad"}` }, l.event),
    l.ip_address || "", Object.keys(l.metadata || {}).length ? JSON.stringify(l.metadata) : "",
  ]);
}

async function renderActivity() {
  const logs = await getAll("/api/audit/logs/mine/");
  app().replaceChildren(
    h("h2", {}, "My security activity"),
    h("p", { class: "small muted" }, "Logins, shares and vault changes on your account. Contents are never logged."),
    table(["When", "User", "Event", "IP", "Details"], logRows(logs)));
}

async function renderAudit() {
  const event = h("input", { placeholder: "event (e.g. login_failed)" });
  const user = h("input", { placeholder: "username" });
  const out = h("div");
  const chain = h("p", { class: "small" });
  const load = async () => {
    const qs = new URLSearchParams();
    if (event.value) qs.set("event", event.value.trim());
    if (user.value) qs.set("username", user.value.trim());
    const page = await api.get(`/api/audit/logs/?${qs}`);
    out.replaceChildren(table(["When", "User", "Event", "IP", "Details"], logRows(page.results)),
      h("p", { class: "tiny muted" }, `Showing ${page.results.length} of ${page.count}`));
  };
  const verify = h("button", { class: "secondary", onclick: async () => {
    const r = await api.get("/api/audit/verify/");
    chain.replaceChildren(r.intact
      ? h("span", { class: "badge ok" }, `✓ hash chain intact (${r.entries_checked} entries)`)
      : h("span", { class: "badge bad" }, `✗ tampering detected at entry #${r.first_tampered_id}`));
  } }, "Verify hash chain");
  app().replaceChildren(
    h("h2", {}, "Audit log"),
    h("div", { class: "toolbar" }, event, user, h("button", { onclick: load }, "Filter"), verify),
    chain, out);
  await load();
}

// ------------------------------------------------------------------ settings

async function renderSettings() {
  const me = await api.get("/api/auth/me/");
  const current = h("input", { type: "password", autocomplete: "current-password" });
  const next = h("input", { type: "password", autocomplete: "new-password" });
  const confirmPw = h("input", { type: "password", autocomplete: "new-password" });
  const change = h("button", { type: "button" }, "Change master password");
  change.addEventListener("click", () => busy(change, "Re-wrapping vault key...", async () => {
    try {
      if (next.value !== confirmPw.value) throw new Error("New passwords don't match.");
      const problems = vc.masterPasswordProblems(next.value, me.username);
      if (problems.length) throw new Error(problems.join(" "));
      const defaults = await api.get("/api/auth/kdf-defaults/");
      const body = await vc.rewrapVaultKey(me, current.value, next.value, defaults);
      const { user, tokens } = await api.post("/api/auth/change-master-password/", body);
      setTokens(tokens);
      state.profile = user;
      toast("Master password changed. Your items didn't need re-encryption.", "success");
    } catch (err) {
      toast(errorMessage(err), "error");
    } finally {
      current.value = next.value = confirmPw.value = "";
    }
  }));

  app().replaceChildren(
    h("section", { class: "card" },
      h("h2", {}, "Your public key fingerprints"),
      h("p", { class: "small muted" }, "Read these to people you share with so they can confirm they have your real keys."),
      h("p", {}, "Encryption (RSA-OAEP): ", h("code", { class: "fp" }, me.encryption_key_fingerprint)),
      h("p", {}, "Signing (RSA-PSS): ", h("code", { class: "fp" }, me.signing_key_fingerprint)),
      h("p", { class: "small muted" }, `KDF: Argon2id, ${me.kdf_memory_kib / 1024} MiB, ${me.kdf_iterations} iterations, parallelism ${me.kdf_parallelism}`)),
    h("section", { class: "card form" },
      h("h2", {}, "Change master password"),
      h("label", {}, "Current master password", current),
      h("label", {}, "New master password", next),
      h("label", {}, "Confirm new master password", confirmPw),
      change));
}

// ------------------------------------------------------------------ admin: users

async function renderUsers() {
  const users = await getAll("/api/auth/admin/users/");
  app().replaceChildren(
    h("h2", {}, "Users"),
    h("p", { class: "small muted" }, "Admins manage roles and access. They can't see anyone's vault contents."),
    table(["Username", "Role", "Active", "Joined", "Last login"], users.map((u) => {
      const role = h("select", {}, ...["user", "auditor", "admin"].map((r) => h("option", { value: r, selected: r === u.role }, r)));
      role.addEventListener("change", async () => {
        try {
          await api.patch(`/api/auth/admin/users/${u.id}/`, { role: role.value });
          toast(`${u.username} is now ${role.value}.`, "success");
        } catch (err) {
          role.value = u.role;
          toast(errorMessage(err), "error");
        }
      });
      const active = h("input", { type: "checkbox", checked: u.is_active });
      active.addEventListener("change", async () => {
        try {
          await api.patch(`/api/auth/admin/users/${u.id}/`, { is_active: active.checked });
        } catch (err) {
          active.checked = !active.checked;
          toast(errorMessage(err), "error");
        }
      });
      return [u.username, role, active, fmtDate(u.date_joined), fmtDate(u.last_login)];
    })));
}

// ------------------------------------------------------------------ admin: AI analyzer

async function renderAnalyzer() {
  const inputs = {
    bandit: h("input", { type: "file", accept: ".json,application/json" }),
    semgrep: h("input", { type: "file", accept: ".json,application/json" }),
    zap: h("input", { type: "file", accept: ".json,application/json" }),
  };
  const useLlm = h("input", { type: "checkbox", checked: true });
  const out = h("div");
  const run = h("button", { type: "button" }, "Analyze");
  run.addEventListener("click", () => busy(run, "Analyzing...", async () => {
    try {
      const body = { use_llm: useLlm.checked };
      for (const [name, input] of Object.entries(inputs)) {
        if (input.files[0]) body[name] = JSON.parse(await input.files[0].text());
      }
      showReport(out, await api.post("/api/analyzer/analyze/", body));
    } catch (err) {
      toast(errorMessage(err), "error");
    }
  }));

  const history = await getAll("/api/analyzer/reports/");
  app().replaceChildren(
    h("h2", {}, "AI security analyzer"),
    h("p", { class: "small muted" }, "Upload JSON reports from Bandit (-f json), Semgrep (--json) or OWASP ZAP (JSON report). Code snippets and anything secret-looking are stripped before findings are sent to the model."),
    h("div", { class: "card form" },
      h("label", {}, "Bandit JSON", inputs.bandit),
      h("label", {}, "Semgrep JSON", inputs.semgrep),
      h("label", {}, "OWASP ZAP JSON", inputs.zap),
      h("label", { class: "inline" }, useLlm, " Use LLM (falls back to the offline knowledge base when no API key is configured)"),
      run),
    out,
    h("h3", {}, "Previous reports"),
    history.length
      ? table(["When", "By", "Engine", "Findings", ""], history.map((r) => [
        fmtDate(r.created_at), r.created_by, r.engine, r.findings_count,
        h("button", { class: "small secondary", onclick: () => showReport(out, r) }, "View"),
      ]))
      : h("p", { class: "muted" }, "No reports yet."));
}

function showReport(container, report) {
  const s = report.summary;
  container.replaceChildren(
    h("section", { class: "card" },
      h("h3", {}, `Report #${report.id} · ${report.engine}`),
      h("p", {}, s.overall),
      h("p", { class: "small" }, ...Object.entries(s.by_severity).filter(([, n]) => n).map(([sev, n]) => h("span", { class: `badge sev-${sev}` }, `${sev}: ${n}`)))),
    ...report.results.map((r) => h("article", { class: `card finding sev-${r.ai_severity}` },
      h("h4", {}, h("span", { class: `badge sev-${r.ai_severity}` }, r.ai_severity), " ", r.title,
        r.likely_false_positive ? h("span", { class: "badge" }, "likely false positive") : null),
      h("p", { class: "tiny muted" }, `${r.tool} ${r.rule_id} ${r.cwe || ""} · ${r.location} · scanner said ${r.severity}`),
      h("p", {}, h("strong", {}, "What it means: "), r.explanation),
      h("p", {}, h("strong", {}, "How to fix: "), r.remediation))));
  container.scrollIntoView({ behavior: "smooth" });
}

// ------------------------------------------------------------------ boot

renderAuth();
