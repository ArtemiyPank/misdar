// Мисдар / Пересчёт — учёт присутствия на построении.
// Ядро приложения: логика, API, обе страницы (RU/HE). Без зависимостей.
// Точки входа: index.js (Cloudflare Workers) и server.js (обычный сервер на Node).

// ─────────────────────────────────────────────────────────────────────────────
// Хелперы
// ─────────────────────────────────────────────────────────────────────────────

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
function randomHex(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return hex(a.buffer); }

async function hashPassword(pw, salt) {
  salt = salt || randomHex(16);
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 10000 }, key, 256);
  return salt + "$" + hex(bits);
}
async function verifyPassword(pw, stored) {
  if (!stored || !pw) return false;
  const salt = stored.split("$")[0];
  return (await hashPassword(pw, salt)) === stored;
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}
function parseCookies(h) {
  const out = {};
  (h || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
const cookie = (name, value, maxAge) => `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

const DAY = 86400 * 1000;
const USER_SESSION_DAYS = 180;
const ADMIN_SESSION_DAYS = 30;

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)",
  "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, leader INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
  "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
  "CREATE TABLE IF NOT EXISTS rollcalls (id INTEGER PRIMARY KEY AUTOINCREMENT, opened_at INTEGER NOT NULL, opened_by TEXT, closed_at INTEGER, closed_by TEXT, report TEXT)",
  "CREATE TABLE IF NOT EXISTS attendance (rollcall_id INTEGER NOT NULL, user_id TEXT NOT NULL, status TEXT NOT NULL, marked_at INTEGER NOT NULL, marked_by TEXT, PRIMARY KEY (rollcall_id, user_id))",
];

// ─────────────────────────────────────────────────────────────────────────────
// Ядро: вся логика и данные (одно подразделение = один экземпляр)
// ─────────────────────────────────────────────────────────────────────────────

export class RollCallCore {
  // sql: объект с exec(query, ...bindings) -> { toArray() }  (API Durable Object SQLite; для Node — адаптер в server.js)
  constructor(sql) {
    this.sql = sql;
    for (const s of SCHEMA) this.sql.exec(s);
    this.fails = new Map(); // ip -> {first, count} — защита от перебора паролей
  }

  // ── settings ──
  get(key) { const r = this.sql.exec("SELECT value FROM settings WHERE key = ?", key).toArray(); return r.length ? r[0].value : null; }
  set(key, value) { this.sql.exec("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value); }
  version() { return parseInt(this.get("version") || "0", 10) || 0; }
  bump() { const v = this.version() + 1; this.set("version", String(v)); return v; }

  // ── rate limit ──
  limited(ip) { const e = this.fails.get(ip); return !!(e && Date.now() - e.first < 15 * 60000 && e.count >= 30); }
  fail(ip) {
    const now = Date.now(); const e = this.fails.get(ip);
    if (!e || now - e.first > 15 * 60000) this.fails.set(ip, { first: now, count: 1 }); else e.count++;
    if (this.fails.size > 5000) this.fails.clear();
  }

  // ── sessions ──
  async session(request, kind) {
    const c = parseCookies(request.headers.get("Cookie"));
    const tok = c[kind === "admin" ? "a" : "s"];
    if (!tok || !/^[0-9a-f]{64}$/.test(tok)) return null;
    const h = await sha256(tok);
    const r = this.sql.exec("SELECT user_id, expires_at FROM sessions WHERE token_hash = ? AND kind = ?", h, kind).toArray();
    if (!r.length || r[0].expires_at < Date.now()) return null;
    if (kind === "admin") return { admin: true };
    const u = this.sql.exec("SELECT id, name, leader FROM users WHERE id = ?", r[0].user_id).toArray();
    return u.length ? u[0] : null;
  }
  async createSession(userId, kind, days) {
    const tok = randomHex(32); const h = await sha256(tok); const now = Date.now();
    this.sql.exec("INSERT INTO sessions(token_hash, user_id, kind, created_at, expires_at) VALUES (?, ?, ?, ?, ?)", h, userId, kind, now, now + days * DAY);
    this.sql.exec("DELETE FROM sessions WHERE expires_at < ?", now);
    return tok;
  }
  async dropSession(request, kind) {
    const c = parseCookies(request.headers.get("Cookie"));
    const tok = c[kind === "admin" ? "a" : "s"];
    if (tok) this.sql.exec("DELETE FROM sessions WHERE token_hash = ?", await sha256(tok));
  }

  // ── data ──
  users() { return this.sql.exec("SELECT id, name, leader FROM users ORDER BY name COLLATE NOCASE").toArray(); }
  userById(id) { const r = this.sql.exec("SELECT id, name, leader FROM users WHERE lower(id) = lower(?)", id).toArray(); return r.length ? r[0] : null; }
  nameOf(id) { if (!id) return null; if (id === "*") return "admin"; const u = this.userById(id); return u ? u.name : null; }
  openRollcall() { const r = this.sql.exec("SELECT id, opened_at, opened_by FROM rollcalls WHERE closed_at IS NULL ORDER BY id DESC LIMIT 1").toArray(); return r.length ? r[0] : null; }
  attendance(rcId) { const m = {}; for (const a of this.sql.exec("SELECT user_id, status, marked_at, marked_by FROM attendance WHERE rollcall_id = ?", rcId).toArray()) m[a.user_id] = a; return m; }
  reports(limit) { return this.sql.exec("SELECT report FROM rollcalls WHERE report IS NOT NULL ORDER BY id DESC LIMIT ?", limit).toArray().map((r) => JSON.parse(r.report)); }

  buildReport(rc, closedAt) {
    const att = this.attendance(rc.id); const present = [], excused = [], missing = [];
    for (const u of this.users()) {
      const s = att[u.id] && att[u.id].status;
      (s === "present" ? present : s === "excused" ? excused : missing).push(u.name);
    }
    return { opened_at: rc.opened_at, closed_at: closedAt, opened_by: this.nameOf(rc.opened_by), total: present.length + excused.length + missing.length, present, excused, missing };
  }
  closeRollcall(rc, by) {
    const report = this.buildReport(rc, Date.now());
    this.sql.exec("UPDATE rollcalls SET closed_at = ?, closed_by = ?, report = ? WHERE id = ?", report.closed_at, by, JSON.stringify(report), rc.id);
    this.bump();
    return report;
  }

  stateFor(me) {
    const v = this.version(); const rc = this.openRollcall();
    const att = rc ? this.attendance(rc.id) : {};
    const users = this.users().map((u) => ({
      id: u.id, name: u.name, leader: !!u.leader,
      status: att[u.id] ? att[u.id].status : null,
      marked_at: att[u.id] ? att[u.id].marked_at : null,
    }));
    const last = this.reports(1)[0] || null;
    return {
      v,
      me: { id: me.id, name: me.name, leader: !!me.leader },
      rollcall: rc ? { id: rc.id, opened_at: rc.opened_at, opened_by: this.nameOf(rc.opened_by) } : null,
      users, last,
    };
  }
  adminState() {
    const rc = this.openRollcall();
    return {
      v: this.version(),
      users: this.users().map((u) => ({ id: u.id, name: u.name, leader: !!u.leader })),
      open: rc ? { id: rc.id, opened_at: rc.opened_at, opened_by: this.nameOf(rc.opened_by), ...this.counts(rc) } : null,
      history: this.reports(20),
    };
  }
  counts(rc) {
    const att = this.attendance(rc.id); let present = 0, excused = 0, total = 0;
    for (const u of this.users()) { total++; const s = att[u.id] && att[u.id].status; if (s === "present") present++; else if (s === "excused") excused++; }
    return { present, excused, missing: total - present - excused, total };
  }
  setStatus(rcId, userId, status, by) {
    if (status) this.sql.exec("INSERT INTO attendance(rollcall_id, user_id, status, marked_at, marked_by) VALUES (?, ?, ?, ?, ?) ON CONFLICT(rollcall_id, user_id) DO UPDATE SET status = excluded.status, marked_at = excluded.marked_at, marked_by = excluded.marked_by", rcId, userId, status, Date.now(), by);
    else this.sql.exec("DELETE FROM attendance WHERE rollcall_id = ? AND user_id = ?", rcId, userId);
    this.bump();
  }

  // ── HTTP ──
  async fetch(request) {
    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/^\/api/, "");
      const method = request.method;
      const ip = request.headers.get("CF-Connecting-IP") || "0";
      let body = {};
      if (method === "POST") {
        if (!(request.headers.get("Content-Type") || "").includes("application/json")) return json({ error: "bad_request" }, 400);
        body = await request.json().catch(() => null);
        if (!body || typeof body !== "object") return json({ error: "bad_request" }, 400);
      } else if (method !== "GET") return json({ error: "method" }, 405);

      const isSetup = !!this.get("admin_hash");

      // первичная настройка
      if (path === "/setup" && method === "POST") {
        if (isSetup) return json({ error: "already_setup" }, 409);
        const ap = String(body.admin_password || ""), sp = String(body.shared_password || "");
        if (ap.length < 4 || sp.length < 4 || ap.length > 100 || sp.length > 100) return json({ error: "invalid" }, 400);
        this.set("admin_hash", await hashPassword(ap));
        this.set("shared_hash", await hashPassword(sp));
        this.bump();
        const tok = await this.createSession("*", "admin", ADMIN_SESSION_DAYS);
        return json({ ok: true }, 200, { "Set-Cookie": cookie("a", tok, ADMIN_SESSION_DAYS * 86400) });
      }
      if (!isSetup) return json({ setup_required: true }, 409);

      if (path.startsWith("/admin/")) return this.admin(path.slice(6), method, body, request, ip);

      // вход солдата
      if (path === "/login" && method === "POST") {
        if (this.limited(ip)) return json({ error: "too_many" }, 429);
        const id = String(body.id || "").trim(), pw = String(body.password || "");
        const ok = id && pw.length <= 100 && (await verifyPassword(pw, this.get("shared_hash")));
        const u = ok ? this.userById(id) : null;
        if (!u) { this.fail(ip); return json({ error: "bad_login" }, 401); }
        const tok = await this.createSession(u.id, "user", USER_SESSION_DAYS);
        return json({ ok: true }, 200, { "Set-Cookie": cookie("s", tok, USER_SESSION_DAYS * 86400) });
      }

      const me = await this.session(request, "user");
      if (!me) return json({ error: "unauthorized" }, 401);

      if (path === "/state" && method === "GET") {
        const v = parseInt(url.searchParams.get("v") || "0", 10) || 0;
        if (v && v === this.version()) return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
        return json(this.stateFor(me));
      }
      if (path === "/logout" && method === "POST") {
        await this.dropSession(request, "user");
        return json({ ok: true }, 200, { "Set-Cookie": cookie("s", "", 0) });
      }
      if (method !== "POST") return json({ error: "not_found" }, 404);

      const rc = this.openRollcall();
      switch (path) {
        case "/mark": {
          if (!rc) return json({ error: "closed" }, 409);
          this.setStatus(rc.id, me.id, body.status === "present" ? "present" : null, me.id);
          return json(this.stateFor(me));
        }
        case "/open": {
          if (!me.leader) return json({ error: "forbidden" }, 403);
          if (rc) return json({ error: "already_open" }, 409);
          this.sql.exec("INSERT INTO rollcalls(opened_at, opened_by) VALUES (?, ?)", Date.now(), me.id);
          const opened = this.openRollcall();
          if (opened) this.setStatus(opened.id, me.id, "present", me.id); // открывший уже на месте (может отменить)
          this.bump();
          return json(this.stateFor(me));
        }
        case "/close": {
          if (!me.leader) return json({ error: "forbidden" }, 403);
          if (!rc) return json({ error: "closed" }, 409);
          this.closeRollcall(rc, me.id);
          return json(this.stateFor(me));
        }
        case "/set": {
          if (!me.leader) return json({ error: "forbidden" }, 403);
          if (!rc) return json({ error: "closed" }, 409);
          const target = this.userById(String(body.user_id || ""));
          if (!target) return json({ error: "no_user" }, 404);
          const st = body.status === "present" || body.status === "excused" ? body.status : null;
          this.setStatus(rc.id, target.id, st, me.id);
          return json(this.stateFor(me));
        }
      }
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "server", detail: String((e && e.message) || e) }, 500);
    }
  }

  async admin(path, method, body, request, ip) {
    if (path === "/login" && method === "POST") {
      if (this.limited(ip)) return json({ error: "too_many" }, 429);
      const ok = await verifyPassword(String(body.password || ""), this.get("admin_hash"));
      if (!ok) { this.fail(ip); return json({ error: "bad_login" }, 401); }
      const tok = await this.createSession("*", "admin", ADMIN_SESSION_DAYS);
      return json({ ok: true }, 200, { "Set-Cookie": cookie("a", tok, ADMIN_SESSION_DAYS * 86400) });
    }
    const adm = await this.session(request, "admin");
    if (!adm) return json({ error: "unauthorized" }, 401);
    if (path === "/state" && method === "GET") return json(this.adminState());
    if (method !== "POST") return json({ error: "not_found" }, 404);

    const validId = (id) => typeof id === "string" && /^\S{1,32}$/.test(id);
    const cleanName = (n) => String(n || "").trim().replace(/\s+/g, " ").slice(0, 60);

    switch (path) {
      case "/logout": {
        await this.dropSession(request, "admin");
        return json({ ok: true }, 200, { "Set-Cookie": cookie("a", "", 0) });
      }
      case "/users/add": {
        const id = String(body.id || "").trim(), name = cleanName(body.name);
        if (!validId(id) || !name) return json({ error: "invalid" }, 400);
        if (this.userById(id)) return json({ error: "exists" }, 409);
        this.sql.exec("INSERT INTO users(id, name, leader, created_at) VALUES (?, ?, ?, ?)", id, name, body.leader ? 1 : 0, Date.now());
        this.bump();
        return json(this.adminState());
      }
      case "/users/import": {
        const lines = String(body.text || "").split(/\r?\n/);
        let added = 0, updated = 0, skipped = 0;
        for (let line of lines) {
          line = line.trim(); if (!line) continue;
          const parts = line.split(/[\s,;]+/).filter(Boolean);
          const id = parts.shift(); const name = cleanName(parts.join(" ")) || id;
          if (!validId(id)) { skipped++; continue; }
          const ex = this.userById(id);
          if (ex) { this.sql.exec("UPDATE users SET name = ? WHERE id = ?", name, ex.id); updated++; }
          else { this.sql.exec("INSERT INTO users(id, name, leader, created_at) VALUES (?, ?, 0, ?)", id, name, Date.now()); added++; }
        }
        this.bump();
        return json({ ...this.adminState(), result: { added, updated, skipped } });
      }
      case "/users/update": {
        const u = this.userById(String(body.id || ""));
        if (!u) return json({ error: "no_user" }, 404);
        if (body.name !== undefined) { const name = cleanName(body.name); if (!name) return json({ error: "invalid" }, 400); this.sql.exec("UPDATE users SET name = ? WHERE id = ?", name, u.id); }
        if (body.leader !== undefined) this.sql.exec("UPDATE users SET leader = ? WHERE id = ?", body.leader ? 1 : 0, u.id);
        this.bump();
        return json(this.adminState());
      }
      case "/users/delete": {
        const u = this.userById(String(body.id || ""));
        if (!u) return json({ error: "no_user" }, 404);
        this.sql.exec("DELETE FROM users WHERE id = ?", u.id);
        this.sql.exec("DELETE FROM sessions WHERE user_id = ? AND kind = 'user'", u.id);
        this.bump();
        return json(this.adminState());
      }
      case "/password": {
        const pw = String(body.password || "");
        if (pw.length < 4 || pw.length > 100) return json({ error: "invalid" }, 400);
        if (body.kind === "admin") this.set("admin_hash", await hashPassword(pw));
        else if (body.kind === "shared") this.set("shared_hash", await hashPassword(pw));
        else return json({ error: "invalid" }, 400);
        return json({ ok: true });
      }
      case "/logout_all": {
        this.sql.exec("DELETE FROM sessions WHERE kind = 'user'");
        return json({ ok: true });
      }
      case "/close": {
        const rc = this.openRollcall();
        if (!rc) return json({ error: "closed" }, 409);
        this.closeRollcall(rc, "*");
        return json(this.adminState());
      }
    }
    return json({ error: "not_found" }, 404);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Статика
// ─────────────────────────────────────────────────────────────────────────────

const MANIFEST = JSON.stringify({
  name: "מסדר", short_name: "מסדר", start_url: "/", display: "standalone",
  background_color: "#f6f7f8", theme_color: "#1f6f3f",
  icons: [{ src: "/icon-192.png", sizes: "192x192", type: "image/png" }, { src: "/icon-512.png", sizes: "512x512", type: "image/png" }],
});

const ICON192 = "iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAYAAABS3GwHAAADyElEQVR42u3d4W0TQRQA4btT+oBOoCMoBXdEOiGVhN9EQonjs+9255t/SJEQl5n3doljr8vBfPnx7XVBlpfL83rk378SHuUgVtKjHMNKfJRDWImPcggr8VEOYSU+yiFs5Meo7OHeRn6UI1iJj/KRaCM/yttgIz/KEWzkRzmCjfwoR7B5VCiz7VUSMOIW2MiPcgQb+VGOwB0A7gCmP6pbwAaADWD6o7oFbADYAKY/qlvABoANYPqjugVsANgAQDoAxx9Uj0E2AGwAQABAkNX5HzYAIABAAIAAAAEAAgAEAAgAEAAgAEAAgAAAAQACAAQACAAQACAAQACAAAABAAIABACchiePAJ/hz6/f//z568/vQ/47vDEWbhL/LaOF4AiE3eT/6NcIAFPKP2IEAkAaAeAuE32ULSAATHWmFwAgAJj+AsCB8o/y8wABIDn5BYC8/ALAXeQf6eUQAkBWfgEgLb8AkEcApn92+guA/Gn5BUD+tPwCIH9afgGQPy2/AMifll8A5E/LLwDkEYDpn53+AiB/Wn4BkD8tvwDIn5ZfAORPyy8A8qflFwD50/ILAHkEYPpnp78AyJ+WXwDkT8svAPKn5RcA+dPyC4D8+WcpAPKneZpNCN9YXMOwH5M628d1mv6OQLuKMNu7HJNfAFeLMEsE5BeASy/5BTDzx3WSXwCnF4n8AhAB+QUgAgjgAPaYaGePwPQXQHYTkF8AD/vmni0C8gsgGwH5j2PY1wLtKc+R4pDfBshejMkvgGwE5BeATQABFCMw/QWQjYD8AshGQH4BZCMgvwCyEZBfANkIyC+AbATkF4BNAAEUIzD9BZCNgPwCyEZAfgFkIyC/ALIRkH9Mhv+FmD04y//ukN8GyIpHfgEQEAIoRiA+AWQjIL8AshGQXwDZCMgvgGwE5BdANgLyCyAbAfkFYBNAAMUIBCSAbATkF0A2AvILIBsB+c+Pl0PvwNuXUxNfAIAjECAAQACAAAABAAIABAAIABAAIABAAIAAAAEAAgAEAAgAEAAgAGDPAF4uz6vHgCIvl+fVBoAjECAAoBqAewCK538bADaARwABOAYhePyxAWAD/K8MYPbpbwPABnivEGDW6W8DwAb4aCnAbNPfBoANcG0xwCzT/90NIALMLP+HjkAiwKzyuwPAHWCvkoDRpv9VG0AEmE3+q49AIsBM8n/qDiACzCL/sizLTTL7lHmMKv6nN4BtgFnkvzkAEWBk+W8+AjkSYVTx7xKAEDCK+HcNQAg4u/gPCUAIOPv98uEXWDHgaOkPDUAQOFL4t/wFwVfmWvVadZAAAAAASUVORK5CYII=";
const ICON512 = "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";

const CSS = String.raw`
:root{--bg:#fff;--card:#fff;--text:#141414;--muted:#777;--line:#e8e8e8;--accent:#1f7a43;--red:#c62828;--pt:#fff}
@media(prefers-color-scheme:dark){:root{--bg:#121212;--card:#1a1a1a;--text:#ececec;--muted:#9a9a9a;--line:#2a2a2a;--accent:#3dab6b;--red:#ef5350}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.45 -apple-system,BlinkMacSystemFont,system-ui,"Segoe UI",Roboto,Arial,sans-serif;padding-bottom:calc(40px + env(safe-area-inset-bottom))}
header{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:14px 20px 4px;padding-top:calc(14px + env(safe-area-inset-top));max-width:520px;margin:0 auto}
h1{font-size:17px;font-weight:600;margin:0}
.hdr-r{display:flex;gap:2px}
main{padding:0 20px;max-width:520px;margin:0 auto}
button{font:inherit;border:0;border-radius:12px;padding:12px 16px;cursor:pointer;touch-action:manipulation;-webkit-tap-highlight-color:transparent;color:var(--text);background:transparent}
button:disabled{opacity:.5}
.primary{background:var(--accent);color:var(--pt);width:100%;font-weight:600}
.secondary{border:1px solid var(--line);width:100%}
.danger{background:var(--red);color:#fff;width:100%;font-weight:600}
.outline-red{border:1px solid var(--line);color:var(--red);width:100%;font-weight:600}
.link{color:var(--muted);padding:4px 6px;font-size:14px}
.icon{color:var(--muted);padding:8px 10px;font-size:14px;font-weight:600}
.hidden{display:none!important}
input,textarea{font:inherit;width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--text)}
input:focus,textarea:focus{outline:none;border-color:var(--accent)}
textarea{min-height:120px;font-family:ui-monospace,Menlo,monospace;font-size:14px}
label{display:block;margin:12px 0}
label span{display:block;font-size:13px;color:var(--muted);margin-bottom:6px}
.card{border:1px solid var(--line);border-radius:14px;padding:16px;margin:14px 0;background:var(--card)}
.card h3{margin:0 0 10px;font-size:15px;font-weight:600}
.banner{border-radius:12px;padding:12px 14px;margin:10px 0;font-size:14px;text-align:center;border:1px solid var(--line);color:var(--muted)}
.banner.open{border-color:var(--accent);color:var(--accent);font-weight:600}
.status{margin:22px 0 4px;font-size:14px;color:var(--muted);text-align:center}
.status.open{color:var(--accent)}
.big{width:100%;padding:28px 16px;font-size:24px;font-weight:700;background:var(--accent);color:var(--pt);border-radius:16px;margin:16px 0}
.marked{text-align:center;margin:26px 0 14px;font-size:21px;font-weight:600;color:var(--accent)}
.marked .link{display:block;margin:4px auto 0;font-weight:400}
.sec{margin-top:26px}
.sec-h{display:flex;align-items:baseline;justify-content:space-between;gap:8px;margin:0 0 2px}
.sec-h h2{margin:0;font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.sec-h .n{font-size:13px;color:var(--muted);white-space:nowrap;direction:ltr;unicode-bidi:isolate}
.list{list-style:none;padding:0;margin:0}
.list li{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:12px 2px;border-bottom:1px solid var(--line)}
.list li.tap{cursor:pointer}
.list li .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.list li .chev{color:var(--muted);font-size:20px;line-height:1}
.list li .chev::before{content:"›"}
[dir=rtl] .list li .chev::before{content:"‹"}
.list.dim li{color:var(--muted)}
.ok-all{padding:14px 2px;color:var(--accent);font-weight:600}
.err{color:var(--red);min-height:1.3em;margin:8px 0 0;font-size:14px}
.muted{color:var(--muted);font-size:14px}
.center{text-align:center}
.row{display:flex;gap:8px;align-items:flex-end}
.row label{flex:1;margin:0}
.row button{width:auto;white-space:nowrap}
.acts{display:flex;gap:2px}
.acts button{padding:8px 9px;font-size:16px;border-radius:8px}
.acts button.on{color:#d19a00}
.net{position:fixed;top:0;left:0;right:0;background:var(--red);color:#fff;text-align:center;font-size:13px;padding:4px;z-index:50}
#modal{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:flex-end;justify-content:center;z-index:20}
#modal .box{background:var(--card);border-radius:18px 18px 0 0;padding:20px 20px calc(20px + env(safe-area-inset-bottom));width:100%;max-width:520px}
#modal p{margin:0 0 12px;font-size:17px;font-weight:600;word-break:break-word}
.m-btns{display:flex;gap:10px;margin-top:14px}
.m-btns.col{flex-direction:column}
.m-btns button{flex:1}
.m-btns .secondary{width:auto}
#toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%);background:#222;color:#fff;padding:10px 18px;border-radius:999px;z-index:30;font-size:15px;white-space:nowrap}
.tag{font-size:12px;color:var(--muted);border:1px solid var(--line);border-radius:6px;padding:1px 6px;margin-inline-start:6px;unicode-bidi:isolate}
pre.rep{white-space:pre-wrap;font:inherit;margin:6px 0 8px}
#leader{margin:30px 0 8px}
#last{margin-top:30px;padding-top:16px;border-top:1px solid var(--line)}
#last h3{margin:0 0 8px;font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
#me{margin-top:28px;font-size:13px}
`;

const HEAD = String.raw`<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#1f6f3f">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<link rel="manifest" href="/manifest.json">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="icon" href="/icon-192.png">`;

// Общий клиентский код (языки, модалка, тост, api) — используется обеими страницами.
// Внутри — без обратных кавычек и ${ } (вставляется в шаблонную строку).
const CLIENT_COMMON = String.raw`
var lang = localStorage.getItem('lang') || (((navigator.language || '').toLowerCase().indexOf('ru') === 0) ? 'ru' : 'he');
function t(k) { return T[lang][k]; }
function f(k, vars) { var s = t(k); Object.keys(vars || {}).forEach(function (x) { s = s.split('{' + x + '}').join(vars[x]); }); return s; }
function $(id) { return document.getElementById(id); }
function show(id, on) { $(id).classList.toggle('hidden', !on); }
function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
function locale() { return lang === 'he' ? 'he-IL' : 'ru-RU'; }
function fmtTime(ts) { return new Date(ts).toLocaleTimeString(locale(), { hour: '2-digit', minute: '2-digit' }); }
function fmtDate(ts) { return new Date(ts).toLocaleDateString(locale(), { day: '2-digit', month: '2-digit' }); }
function api(path, body) {
  var opts = { credentials: 'same-origin' };
  if (body !== undefined) { opts.method = 'POST'; opts.headers = { 'Content-Type': 'application/json' }; opts.body = JSON.stringify(body); }
  return fetch('/api/' + path, opts).then(function (r) {
    if (r.status === 204) return { _status: 204 };
    return r.json().catch(function () { return {}; }).then(function (j) { j._status = r.status; return j; });
  });
}
var modalCb = null;
function ask(text, opts) {
  opts = opts || {};
  $('m-text').textContent = text;
  var inp = $('m-input'); inp.value = opts.value || ''; inp.type = opts.password ? 'password' : 'text'; show('m-input', !!opts.input);
  var btns = $('m-btns'); btns.innerHTML = '';
  var list = opts.buttons || [{ label: t('cancel'), value: null, cls: 'secondary' }, { label: opts.ok || t('confirm'), value: true, cls: opts.danger ? 'danger' : 'primary' }];
  btns.className = 'm-btns' + (list.length > 2 ? ' col' : '');
  list.forEach(function (b) {
    var el = document.createElement('button'); el.textContent = b.label; el.className = b.cls || 'secondary';
    el.onclick = function () { show('modal', false); var cb = modalCb; modalCb = null; if (cb) cb(b.value === true && opts.input ? inp.value : b.value); };
    btns.appendChild(el);
  });
  show('modal', true);
  if (opts.input) setTimeout(function () { inp.focus(); }, 60);
  return new Promise(function (res) { modalCb = res; });
}
$('modal').addEventListener('click', function (e) { if (e.target.id === 'modal') { show('modal', false); var cb = modalCb; modalCb = null; if (cb) cb(null); } });
$('m-input').addEventListener('keydown', function (e) { if (e.key === 'Enter') { var b = $('m-btns').lastChild; if (b) b.click(); } });
var toastT;
function toast(msg) { var el = $('toast'); el.textContent = msg; show('toast', true); clearTimeout(toastT); toastT = setTimeout(function () { show('toast', false); }, 2200); }
function copyText(s) {
  var done = function () { toast(t('copied')); };
  var fb = function () { var ta = document.createElement('textarea'); ta.value = s; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.focus(); ta.select(); try { document.execCommand('copy'); } catch (e) {} document.body.removeChild(ta); done(); };
  if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(s).then(done, fb); else fb();
}
function reportText(r) {
  var R = t('report');
  var lines = [R.title + ' ' + fmtDate(r.closed_at || r.opened_at) + ' ' + fmtTime(r.opened_at) + (r.closed_at ? ('–' + fmtTime(r.closed_at)) : ''),
    R.present + ': ' + r.present.length + '/' + r.total,
    R.missing + ': ' + (r.missing.length ? r.missing.join(', ') : R.none)];
  if (r.excused.length) lines.push(R.excused + ': ' + r.excused.join(', '));
  return lines.join('\n');
}
function applyLang() {
  document.documentElement.lang = lang; document.documentElement.dir = lang === 'he' ? 'rtl' : 'ltr';
  $('lang').textContent = lang === 'he' ? 'RU' : 'עב';
  document.title = t('title'); $('h-title').textContent = t('title');
  var els = document.querySelectorAll('[data-t]'); for (var i = 0; i < els.length; i++) els[i].textContent = t(els[i].getAttribute('data-t'));
  var ph = document.querySelectorAll('[data-ph]'); for (var k = 0; k < ph.length; k++) ph[k].setAttribute('placeholder', t(ph[k].getAttribute('data-ph')));
  if (typeof render === 'function') render();
}
$('lang').onclick = function () { lang = lang === 'he' ? 'ru' : 'he'; localStorage.setItem('lang', lang); applyLang(); };
`;

// ── Главная страница ──
const MAIN_HTML = String.raw`<!doctype html>
<html lang="he" dir="rtl">
<head>
${HEAD}
<title>מסדר</title>
<style>${CSS}</style>
</head>
<body>
<div id="net" class="net hidden"></div>
<header>
  <h1 id="h-title">מסדר</h1>
  <div class="hdr-r"><button id="lang" class="icon">RU</button><button id="logout" class="icon hidden">⎋</button></div>
</header>
<main>
  <p id="msg" class="center muted hidden"></p>
  <form id="login" class="hidden" autocomplete="on" style="margin-top:28px">
    <label><span data-t="id"></span><input id="l-id" autocomplete="username" autocapitalize="off" autocorrect="off" spellcheck="false" inputmode="text"></label>
    <label><span data-t="password"></span><input id="l-pass" type="password" autocomplete="current-password"></label>
    <button id="l-btn" class="primary" type="submit" data-t="enter" style="margin-top:8px"></button>
    <p id="l-err" class="err"></p>
  </form>
  <section id="app" class="hidden">
    <div id="status" class="status"></div>
    <div id="action"></div>
    <div id="missing" class="sec hidden"></div>
    <div id="excused" class="sec hidden"></div>
    <div id="leader" class="hidden"></div>
    <div id="last" class="hidden"></div>
    <p id="me" class="center muted"></p>
  </section>
</main>
<div id="modal" class="hidden"><div class="box"><p id="m-text"></p><input id="m-input" class="hidden" autocapitalize="off"><div id="m-btns" class="m-btns"></div></div></div>
<div id="toast" class="hidden"></div>
<script>
(function () {
'use strict';
var T = {
  he: { title: 'מסדר', id: 'מזהה (ID)', password: 'סיסמה', enter: 'כניסה',
    badLogin: 'מזהה או סיסמה שגויים', tooMany: 'יותר מדי ניסיונות, נסה שוב בעוד כמה דקות', offline: 'אין חיבור לשרת',
    notSetup: 'האתר עדיין לא הוגדר. פתח /admin והגדר סיסמאות.',
    open: 'מסדר פתוח', closed: 'אין מסדר פתוח',
    here: 'אני כאן', marked: 'מסומן', unmark: 'בטל סימון', excusedYou: 'אתה מסומן "באישור"',
    missing: 'חסרים', excused: 'באישור', all: 'כולם נוכחים',
    openBtn: 'פתח מסדר', closeBtn: 'סגור מסדר', openQ: 'לפתוח מסדר?', closeQ: 'לסגור את המסדר?', closeMissing: 'חסרים:',
    confirm: 'אישור', cancel: 'ביטול', last: 'מסדר אחרון', copy: 'העתק', copied: 'הועתק',
    logout: 'יציאה', logoutQ: 'לצאת מהחשבון?', setPresent: 'נוכח', setExcused: 'באישור', setNone: 'הסר סימון', leaderTag: 'אחראי',
    report: { title: 'מסדר', present: 'נוכחים', missing: 'חסרים', excused: 'באישור', none: 'אין' } },
  ru: { title: 'Пересчёт', id: 'ID', password: 'Пароль', enter: 'Войти',
    badLogin: 'Неверный ID или пароль', tooMany: 'Слишком много попыток, попробуй через пару минут', offline: 'Нет связи с сервером',
    notSetup: 'Сайт ещё не настроен. Открой /admin и задай пароли.',
    open: 'Пересчёт открыт', closed: 'Пересчёт не открыт',
    here: 'Я на месте', marked: 'Отмечен', unmark: 'Отменить', excusedYou: 'Ты отмечен «по уважительной»',
    missing: 'Не отметились', excused: 'По уважительной', all: 'Все на месте',
    openBtn: 'Открыть пересчёт', closeBtn: 'Закрыть пересчёт', openQ: 'Открыть пересчёт?', closeQ: 'Закрыть пересчёт?', closeMissing: 'Не отметились:',
    confirm: 'Подтвердить', cancel: 'Отмена', last: 'Последний пересчёт', copy: 'Скопировать', copied: 'Скопировано',
    logout: 'Выйти', logoutQ: 'Выйти из аккаунта?', setPresent: 'На месте', setExcused: 'По уважительной', setNone: 'Снять отметку', leaderTag: 'главный',
    report: { title: 'Пересчёт', present: 'На месте', missing: 'Отсутствуют', excused: 'По уважительной', none: 'нет' } }
};
${CLIENT_COMMON}
var state = null, version = 0, me = null, timer = null;

function loggedIn(on) { show('login', !on); show('app', on); show('logout', on); if (on) show('msg', false); }
function setOffline(v) { $('net').textContent = t('offline'); show('net', v); }

function load(force) {
  return api('state?v=' + (force ? 0 : version)).then(function (j) {
    setOffline(false);
    if (j._status === 204) return;
    if (j._status === 401) { state = null; me = null; version = 0; loggedIn(false); return; }
    if (j._status === 409 && j.setup_required) { loggedIn(false); show('login', false); $('msg').textContent = t('notSetup'); show('msg', true); return; }
    if (j._status !== 200) return;
    state = j; version = j.v; me = j.me; loggedIn(true); render();
  }).catch(function () { setOffline(true); });
}
function schedule() { clearTimeout(timer); if (document.hidden || !me) return; timer = setTimeout(tick, (state && state.rollcall) ? 2500 : 10000); }
function tick() { load().then(schedule, schedule); }
document.addEventListener('visibilitychange', function () { if (document.hidden) clearTimeout(timer); else load(true).then(schedule, schedule); });
window.addEventListener('online', function () { load(true).then(schedule, schedule); });

function act(path, body) { return api(path, body).then(function (j) { if (j._status === 409 || j._status === 403) toast(t('closed')); return load(true); }); }

function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
function secHeader(title, count, extra) {
  var h = el('div', 'sec-h'); h.appendChild(el('h2', '', title));
  var r = el('div', ''); r.style.display = 'flex'; r.style.gap = '10px'; r.style.alignItems = 'baseline';
  if (extra) r.appendChild(extra);
  r.appendChild(el('span', 'n', count)); h.appendChild(r); return h;
}
function peopleList(arr, dim) {
  var ul = el('ul', 'list' + (dim ? ' dim' : ''));
  arr.forEach(function (u) {
    var li = el('li', me.leader ? 'tap' : '');
    var n = el('span', 'nm', u.name); if (u.leader) n.appendChild(el('span', 'tag', t('leaderTag'))); li.appendChild(n);
    if (me.leader) { li.appendChild(el('span', 'chev')); li.onclick = function () { pick(u); }; }
    ul.appendChild(li);
  });
  return ul;
}
function pick(u) {
  var btns = [];
  if (u.status !== 'present') btns.push({ label: t('setPresent'), value: 'present', cls: 'primary' });
  if (u.status !== 'excused') btns.push({ label: t('setExcused'), value: 'excused', cls: 'secondary' });
  if (u.status) btns.push({ label: t('setNone'), value: 'none', cls: 'secondary' });
  btns.push({ label: t('cancel'), value: null, cls: 'secondary' });
  ask(u.name, { buttons: btns }).then(function (v) { if (!v) return; act('set', { user_id: u.id, status: v === 'none' ? null : v }); });
}
function liveReport(present, excused, missing) {
  var nm = function (u) { return u.name; };
  return { opened_at: state.rollcall.opened_at, closed_at: null, total: state.users.length, present: present.map(nm), excused: excused.map(nm), missing: missing.map(nm) };
}

function render() {
  if (!state || !me) return;
  var rc = state.rollcall, users = state.users;
  var present = [], excused = [], missing = [], mine = null;
  users.forEach(function (u) { if (u.id === me.id) mine = u; if (u.status === 'present') present.push(u); else if (u.status === 'excused') excused.push(u); else missing.push(u); });
  $('me').textContent = me.name + (me.leader ? ' · ' + t('leaderTag') : '');

  var s = $('status');
  if (rc) { s.className = 'status open'; s.textContent = '● ' + t('open') + ' · ' + fmtTime(rc.opened_at) + (rc.opened_by ? ' · ' + rc.opened_by : ''); }
  else { s.className = 'status'; s.textContent = t('closed'); }

  var a = $('action'); a.innerHTML = '';
  if (rc) {
    if (mine && mine.status === 'present') {
      var m = el('div', 'marked', '✓ ' + t('marked') + ' · ' + fmtTime(mine.marked_at));
      var ub = el('button', 'link', t('unmark'));
      ub.onclick = function () { ask(t('unmark') + '?', { danger: true }).then(function (ok) { if (ok) act('mark', { status: null }); }); };
      m.appendChild(ub); a.appendChild(m);
    } else {
      var btn = el('button', 'big', t('here'));
      btn.onclick = function () { btn.disabled = true; act('mark', { status: 'present' }).then(function () { btn.disabled = false; }, function () { btn.disabled = false; }); };
      a.appendChild(btn);
      if (mine && mine.status === 'excused') a.appendChild(el('p', 'muted center', t('excusedYou')));
    }

    var M = $('missing'); M.innerHTML = '';
    var copyBtn = null;
    if (me.leader) { copyBtn = el('button', 'link', t('copy')); copyBtn.id = 'copy-live'; copyBtn.onclick = function () { copyText(reportText(liveReport(present, excused, missing))); }; }
    M.appendChild(secHeader(t('missing'), missing.length + ' / ' + users.length, copyBtn));
    if (missing.length) M.appendChild(peopleList(missing, false)); else M.appendChild(el('div', 'ok-all', '✓ ' + t('all')));
    show('missing', true);

    var E = $('excused'); E.innerHTML = '';
    if (excused.length) { E.appendChild(secHeader(t('excused'), String(excused.length))); E.appendChild(peopleList(excused, true)); show('excused', true); }
    else show('excused', false);
  } else { show('missing', false); show('excused', false); }

  var ld = $('leader'); ld.innerHTML = '';
  if (me.leader) {
    var lb = el('button', rc ? 'outline-red' : 'primary', rc ? t('closeBtn') : t('openBtn'));
    lb.onclick = function () {
      if (rc) {
        var names = missing.map(function (u) { return u.name; });
        var txt = t('closeQ') + (names.length ? ' ' + t('closeMissing') + ' ' + names.slice(0, 15).join(', ') + (names.length > 15 ? ' +' + (names.length - 15) : '') : '');
        ask(txt, { danger: true }).then(function (ok) { if (ok) act('close', {}); });
      } else ask(t('openQ')).then(function (ok) { if (ok) act('open', {}); });
    };
    ld.appendChild(lb); show('leader', true);
  } else show('leader', false);

  var last = state.last;
  if (last && !rc) {
    var L = $('last'); L.innerHTML = '';
    L.appendChild(el('h3', '', t('last')));
    L.appendChild(el('pre', 'rep', reportText(last)));
    var cb = el('button', 'link', t('copy')); cb.style.padding = '4px 0'; cb.onclick = function () { copyText(reportText(last)); }; L.appendChild(cb);
    show('last', true);
  } else show('last', false);
}

$('login').onsubmit = function (e) {
  e.preventDefault();
  var id = $('l-id').value.trim(), p = $('l-pass').value;
  if (!id || !p) return;
  $('l-err').textContent = ''; $('l-btn').disabled = true;
  api('login', { id: id, password: p }).then(function (j) {
    $('l-btn').disabled = false;
    if (j._status === 200) { $('l-pass').value = ''; return load(true).then(schedule); }
    $('l-err').textContent = j._status === 429 ? t('tooMany') : (j._status === 409 ? t('notSetup') : t('badLogin'));
  }).catch(function () { $('l-btn').disabled = false; $('l-err').textContent = t('offline'); });
};
$('logout').onclick = function () { ask(t('logoutQ'), { danger: true }).then(function (ok) { if (ok) api('logout', {}).then(function () { state = null; me = null; version = 0; loggedIn(false); }); }); };

applyLang();
load(true).then(schedule, schedule);
})();
</script>
</body>
</html>`;

// ── Админка ──
const ADMIN_HTML = String.raw`<!doctype html>
<html lang="he" dir="rtl">
<head>
${HEAD}
<title>ניהול</title>
<style>${CSS}</style>
</head>
<body>
<header>
  <h1 id="h-title">ניהול</h1>
  <div class="hdr-r"><button id="lang" class="icon">RU</button><button id="logout" class="icon hidden">⎋</button></div>
</header>
<main>
  <form id="setup" class="card hidden">
    <h3 data-t="setup"></h3>
    <p class="muted" data-t="setupHint"></p>
    <label><span data-t="adminPass"></span><input id="s-admin" type="password" autocomplete="new-password"></label>
    <label><span data-t="sharedPass"></span><input id="s-shared" type="password" autocomplete="new-password"></label>
    <button class="primary" type="submit" data-t="save"></button>
    <p id="s-err" class="err"></p>
  </form>
  <form id="login" class="card hidden">
    <h3 data-t="login"></h3>
    <label><span data-t="adminPass"></span><input id="l-pass" type="password" autocomplete="current-password"></label>
    <button id="l-btn" class="primary" type="submit" data-t="enter"></button>
    <p id="l-err" class="err"></p>
  </form>
  <section id="app" class="hidden">
    <div id="open" class="banner"></div>
    <div id="open-act"></div>

    <div class="card">
      <h3><span data-t="people"></span> <span id="cnt" class="muted"></span></h3>
      <form id="add" class="row">
        <label><span data-t="id"></span><input id="a-id" autocapitalize="off" autocorrect="off" spellcheck="false"></label>
        <label><span data-t="name"></span><input id="a-name"></label>
        <button class="primary" type="submit" data-t="add"></button>
      </form>
      <p id="a-err" class="err"></p>
      <ul id="people" class="list"></ul>
    </div>

    <div class="card">
      <h3 data-t="importT"></h3>
      <p class="muted" data-t="importHint"></p>
      <textarea id="imp" data-ph="importPh"></textarea>
      <button id="imp-btn" class="secondary" style="margin-top:10px" data-t="importBtn"></button>
    </div>

    <div class="card">
      <h3 data-t="passwords"></h3>
      <button id="pw-shared" class="secondary" data-t="changeShared"></button>
      <button id="pw-admin" class="secondary" style="margin-top:8px" data-t="changeAdmin"></button>
      <button id="logout-all" class="secondary" style="margin-top:8px" data-t="logoutAll"></button>
    </div>

    <div class="card">
      <h3 data-t="link"></h3>
      <p id="site" class="muted" style="word-break:break-all"></p>
      <button id="copy-link" class="secondary" data-t="copy"></button>
    </div>

    <div class="card">
      <h3 data-t="history"></h3>
      <div id="hist"></div>
    </div>
  </section>
</main>
<div id="modal" class="hidden"><div class="box"><p id="m-text"></p><input id="m-input" class="hidden" autocapitalize="off"><div id="m-btns" class="m-btns"></div></div></div>
<div id="toast" class="hidden"></div>
<script>
(function () {
'use strict';
var T = {
  he: { title: 'ניהול', setup: 'הגדרה ראשונית', setupHint: 'קבע סיסמת ניהול (רק לך) וסיסמה משותפת (לכניסת כולם). לפחות 4 תווים.',
    adminPass: 'סיסמת ניהול', sharedPass: 'סיסמה משותפת', save: 'שמור', login: 'כניסה', enter: 'כניסה',
    badLogin: 'סיסמה שגויה', tooMany: 'יותר מדי ניסיונות, נסה שוב בעוד כמה דקות', offline: 'אין חיבור לשרת', invalid: 'נתונים לא תקינים', exists: 'מזהה כזה כבר קיים',
    people: 'אנשים', add: 'הוסף', id: 'מזהה', name: 'שם', leader: 'אחראי', empty: 'אין אף אחד עדיין — הוסף אנשים או ייבא רשימה.',
    makeLeaderQ: 'להפוך את {n} לאחראי (יוכל לפתוח ולסגור מסדר)?', unmakeLeaderQ: 'להסיר את {n} מהאחראים?',
    rename: 'שנה שם', renameQ: 'שם חדש עבור {n}:', del: 'מחק', delQ: 'למחוק את {n}?',
    importT: 'ייבוא רשימה', importHint: 'שורה לכל אדם: מזהה, ואז שם. מזהה קיים — השם יעודכן.', importPh: '1234 ישראל ישראלי', importBtn: 'ייבא', importQ: 'לייבא {n} שורות?', imported: 'נוסף: {a}, עודכן: {u}, דולג: {s}',
    passwords: 'סיסמאות', changeShared: 'שנה סיסמה משותפת', changeAdmin: 'שנה סיסמת ניהול', newPass: 'סיסמה חדשה (לפחות 4 תווים):', saved: 'נשמר',
    logoutAll: 'נתק את כולם', logoutAllQ: 'לנתק את כל החיילים? הם יצטרכו להיכנס מחדש.',
    link: 'קישור לחיילים', copy: 'העתק', copied: 'הועתק', history: 'היסטוריה', noHistory: 'עדיין אין מסדרים',
    openNow: 'מסדר פתוח מאז {t} · נוכחים {p}/{all}', noOpen: 'אין מסדר פתוח', closeBtn: 'סגור מסדר', closeQ: 'לסגור את המסדר?',
    logout: 'יציאה', logoutQ: 'לצאת מהניהול?', cancel: 'ביטול', confirm: 'אישור',
    report: { title: 'מסדר', present: 'נוכחים', missing: 'חסרים', excused: 'באישור', none: 'אין' } },
  ru: { title: 'Админка', setup: 'Первичная настройка', setupHint: 'Задай пароль админа (только для тебя) и общий пароль (для входа всех). Минимум 4 символа.',
    adminPass: 'Пароль админа', sharedPass: 'Общий пароль', save: 'Сохранить', login: 'Вход', enter: 'Войти',
    badLogin: 'Неверный пароль', tooMany: 'Слишком много попыток, попробуй через пару минут', offline: 'Нет связи с сервером', invalid: 'Некорректные данные', exists: 'Такой ID уже есть',
    people: 'Люди', add: 'Добавить', id: 'ID', name: 'Имя', leader: 'главный', empty: 'Пока никого нет — добавь людей или импортируй список.',
    makeLeaderQ: 'Сделать {n} главным (сможет открывать и закрывать пересчёт)?', unmakeLeaderQ: 'Снять {n} с главных?',
    rename: 'Переименовать', renameQ: 'Новое имя для {n}:', del: 'Удалить', delQ: 'Удалить {n}?',
    importT: 'Импорт списка', importHint: 'По строке на человека: ID, затем имя. Если ID уже есть — имя обновится.', importPh: '1234 Иван Иванов', importBtn: 'Импортировать', importQ: 'Импортировать {n} строк?', imported: 'Добавлено: {a}, обновлено: {u}, пропущено: {s}',
    passwords: 'Пароли', changeShared: 'Сменить общий пароль', changeAdmin: 'Сменить пароль админа', newPass: 'Новый пароль (минимум 4 символа):', saved: 'Сохранено',
    logoutAll: 'Разлогинить всех', logoutAllQ: 'Выкинуть всех из аккаунтов? Им придётся войти заново.',
    link: 'Ссылка для солдат', copy: 'Скопировать', copied: 'Скопировано', history: 'История', noHistory: 'Пересчётов ещё не было',
    openNow: 'Пересчёт открыт с {t} · на месте {p}/{all}', noOpen: 'Пересчёт не открыт', closeBtn: 'Закрыть пересчёт', closeQ: 'Закрыть пересчёт?',
    logout: 'Выйти', logoutQ: 'Выйти из админки?', cancel: 'Отмена', confirm: 'Подтвердить',
    report: { title: 'Пересчёт', present: 'На месте', missing: 'Отсутствуют', excused: 'По уважительной', none: 'нет' } }
};
${CLIENT_COMMON}
var st = null;

function mode(m) { show('setup', m === 'setup'); show('login', m === 'login'); show('app', m === 'app'); show('logout', m === 'app'); }
function load() {
  return api('admin/state').then(function (j) {
    if (j._status === 409 && j.setup_required) { mode('setup'); return; }
    if (j._status === 401) { mode('login'); return; }
    if (j._status !== 200) return;
    st = j; mode('app'); render();
  }).catch(function () { toast(t('offline')); });
}
function act(path, body) {
  return api(path, body).then(function (j) {
    if (j._status === 200) { if (j.users) { st = j; render(); } return j; }
    if (j._status === 401) { mode('login'); return j; }
    toast(j._status === 409 ? t('exists') : t('invalid')); return j;
  }).catch(function () { toast(t('offline')); return {}; });
}

function render() {
  if (!st) return;
  var o = $('open'); var oa = $('open-act'); oa.innerHTML = '';
  if (st.open) {
    o.className = 'banner open'; o.textContent = f('openNow', { t: fmtTime(st.open.opened_at), p: st.open.present, all: st.open.total });
    var cb = document.createElement('button'); cb.className = 'danger'; cb.textContent = t('closeBtn');
    cb.onclick = function () { ask(t('closeQ'), { danger: true }).then(function (ok) { if (ok) act('admin/close', {}); }); };
    oa.appendChild(cb);
  } else { o.className = 'banner'; o.textContent = t('noOpen'); }

  $('cnt').textContent = '(' + st.users.length + ')';
  var ul = $('people'); ul.innerHTML = '';
  if (!st.users.length) { var li0 = document.createElement('li'); li0.className = 'muted'; li0.textContent = t('empty'); ul.appendChild(li0); }
  st.users.forEach(function (u) {
    var li = document.createElement('li');
    var n = document.createElement('span'); n.className = 'nm'; n.textContent = u.name;
    var idt = document.createElement('span'); idt.className = 'tag'; idt.textContent = u.id; n.appendChild(idt);
    if (u.leader) { var lt = document.createElement('span'); lt.className = 'tag'; lt.textContent = t('leader'); n.appendChild(lt); }
    li.appendChild(n);
    var acts = document.createElement('div'); acts.className = 'acts';
    var b1 = document.createElement('button'); b1.textContent = '★'; b1.className = u.leader ? 'on' : ''; b1.title = t('leader');
    b1.onclick = function () { ask(f(u.leader ? 'unmakeLeaderQ' : 'makeLeaderQ', { n: u.name })).then(function (ok) { if (ok) act('admin/users/update', { id: u.id, leader: !u.leader }); }); };
    var b2 = document.createElement('button'); b2.textContent = '✎'; b2.title = t('rename');
    b2.onclick = function () { ask(f('renameQ', { n: u.name }), { input: true, value: u.name, ok: t('save') }).then(function (v) { if (v && v.trim() && v.trim() !== u.name) act('admin/users/update', { id: u.id, name: v.trim() }); }); };
    var b3 = document.createElement('button'); b3.textContent = '✕'; b3.title = t('del');
    b3.onclick = function () { ask(f('delQ', { n: u.name }), { danger: true, ok: t('del') }).then(function (ok) { if (ok) act('admin/users/delete', { id: u.id }); }); };
    acts.appendChild(b1); acts.appendChild(b2); acts.appendChild(b3); li.appendChild(acts);
    ul.appendChild(li);
  });

  $('site').textContent = location.origin + '/';

  var h = $('hist'); h.innerHTML = '';
  if (!st.history.length) { var p = document.createElement('p'); p.className = 'muted'; p.textContent = t('noHistory'); p.style.margin = '0'; h.appendChild(p); }
  st.history.forEach(function (r, i) {
    var d = document.createElement('div'); if (i) { d.style.borderTop = '1px solid var(--line)'; d.style.paddingTop = '8px'; d.style.marginTop = '8px'; }
    var pre = document.createElement('pre'); pre.className = 'rep'; pre.textContent = reportText(r); d.appendChild(pre);
    var cb = document.createElement('button'); cb.className = 'link'; cb.textContent = t('copy'); cb.onclick = function () { copyText(reportText(r)); }; d.appendChild(cb);
    h.appendChild(d);
  });
}

$('setup').onsubmit = function (e) {
  e.preventDefault(); $('s-err').textContent = '';
  var a = $('s-admin').value, s = $('s-shared').value;
  if (a.length < 4 || s.length < 4) { $('s-err').textContent = t('invalid'); return; }
  api('setup', { admin_password: a, shared_password: s }).then(function (j) { if (j._status === 200) { $('s-admin').value = ''; $('s-shared').value = ''; load(); } else $('s-err').textContent = t('invalid'); }).catch(function () { $('s-err').textContent = t('offline'); });
};
$('login').onsubmit = function (e) {
  e.preventDefault(); $('l-err').textContent = ''; $('l-btn').disabled = true;
  api('admin/login', { password: $('l-pass').value }).then(function (j) {
    $('l-btn').disabled = false;
    if (j._status === 200) { $('l-pass').value = ''; load(); }
    else $('l-err').textContent = j._status === 429 ? t('tooMany') : t('badLogin');
  }).catch(function () { $('l-btn').disabled = false; $('l-err').textContent = t('offline'); });
};
$('add').onsubmit = function (e) {
  e.preventDefault(); $('a-err').textContent = '';
  var id = $('a-id').value.trim(), name = $('a-name').value.trim();
  if (!id || !name) return;
  $('a-id').value = ''; $('a-name').value = ''; $('a-id').focus();
  act('admin/users/add', { id: id, name: name }).then(function (j) { if (j._status !== 200) { $('a-id').value = id; $('a-name').value = name; } });
};
$('imp-btn').onclick = function () {
  var txt = $('imp').value; var n = txt.split(/\r?\n/).filter(function (l) { return l.trim(); }).length;
  if (!n) return;
  ask(f('importQ', { n: n })).then(function (ok) {
    if (!ok) return;
    act('admin/users/import', { text: txt }).then(function (j) { if (j._status === 200) { $('imp').value = ''; toast(f('imported', { a: j.result.added, u: j.result.updated, s: j.result.skipped })); } });
  });
};
function changePw(kind) {
  ask(t('newPass'), { input: true, password: true, ok: t('save') }).then(function (v) {
    if (v === null || v === undefined) return;
    if (v.length < 4) { toast(t('invalid')); return; }
    act('admin/password', { kind: kind, password: v }).then(function (j) { if (j._status === 200) toast(t('saved')); });
  });
}
$('pw-shared').onclick = function () { changePw('shared'); };
$('pw-admin').onclick = function () { changePw('admin'); };
$('logout-all').onclick = function () { ask(t('logoutAllQ'), { danger: true }).then(function (ok) { if (ok) act('admin/logout_all', {}).then(function (j) { if (j._status === 200) toast(t('saved')); }); }); };
$('copy-link').onclick = function () { copyText(location.origin + '/'); };
$('logout').onclick = function () { ask(t('logoutQ'), { danger: true }).then(function (ok) { if (ok) api('admin/logout', {}).then(function () { mode('login'); }); }); };

document.addEventListener('visibilitychange', function () { if (!document.hidden && st) load(); });
applyLang();
load();
})();
</script>
</body>
</html>`;

// ─────────────────────────────────────────────────────────────────────────────
// Страницы и статика (общее для Cloudflare и Node)
// ─────────────────────────────────────────────────────────────────────────────

export function handleStatic(request) {
  const p = new URL(request.url).pathname;
  if (p === "/" || p === "/index.html") return page(MAIN_HTML);
  if (p === "/admin" || p === "/admin/") return page(ADMIN_HTML);
  if (p === "/healthz") return new Response("ok", { headers: { "Cache-Control": "no-store" } });
  if (p === "/manifest.json") return new Response(MANIFEST, { headers: { "Content-Type": "application/manifest+json", "Cache-Control": "public, max-age=3600" } });
  if (p === "/icon-192.png" || p === "/apple-touch-icon.png") return png(ICON192);
  if (p === "/icon-512.png") return png(ICON512);
  return null;
}

function page(html) {
  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  });
}

function png(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Response(bytes, { headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" } });
}
