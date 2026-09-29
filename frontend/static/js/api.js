// Thin JSON client for the Django REST API. Tokens live only in memory.

let tokens = null;
let onSessionExpired = () => {};

export function setTokens(t) {
  tokens = t;
}

export function clearTokens() {
  tokens = null;
}

export function getRefreshToken() {
  return tokens && tokens.refresh;
}

export function onExpired(fn) {
  onSessionExpired = fn;
}

export class ApiError extends Error {
  constructor(status, data) {
    super(ApiError.describe(data) || `Request failed (${status})`);
    this.status = status;
    this.data = data;
  }

  static describe(data) {
    if (!data) return "";
    if (typeof data === "string") return data;
    if (data.detail) return String(data.detail);
    return Object.entries(data)
      .map(([k, v]) => `${k === "non_field_errors" ? "" : k + ": "}${Array.isArray(v) ? v.join(" ") : v}`)
      .join("; ");
  }
}

// Refresh tokens rotate and the old one is blacklisted, so parallel 401s must share a
// single refresh call; a second call with the already-used token would fail.
let refreshing = null;

function refresh() {
  if (!refreshing) refreshing = doRefresh().finally(() => (refreshing = null));
  return refreshing;
}

async function doRefresh() {
  if (!tokens || !tokens.refresh) return false;
  const res = await fetch("/api/auth/refresh/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh: tokens.refresh }),
  });
  if (!res.ok) return false;
  const data = await res.json();
  tokens = { access: data.access, refresh: data.refresh || tokens.refresh };
  return true;
}

export async function request(method, path, body, { retry = true } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (tokens && tokens.access) headers.Authorization = `Bearer ${tokens.access}`;
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
  if (res.status === 401 && retry && tokens) {
    if (await refresh()) return request(method, path, body, { retry: false });
    onSessionExpired();
  }
  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) throw new ApiError(res.status, data);
  return data;
}

export const api = {
  get: (p) => request("GET", p),
  post: (p, b = {}) => request("POST", p, b),
  put: (p, b) => request("PUT", p, b),
  patch: (p, b) => request("PATCH", p, b),
  del: (p) => request("DELETE", p),
};

// DRF LimitOffsetPagination -> plain array (follows `next` links).
export async function getAll(path) {
  let out = [];
  let page = await api.get(path);
  if (Array.isArray(page)) return page;
  out = out.concat(page.results);
  while (page.next) {
    const url = new URL(page.next);
    page = await api.get(url.pathname + url.search);
    out = out.concat(page.results);
  }
  return out;
}
