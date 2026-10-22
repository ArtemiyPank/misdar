// Точка входа для обычного Linux-сервера (Node ≥ 22.13, без npm-зависимостей).
// Слушает только 127.0.0.1 — наружу смотрит nginx/caddy с HTTPS.
//
//   PORT=8793 HOST=127.0.0.1 DATA_DIR=/var/lib/misdar node server.js

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { RollCallCore, handleStatic } from "./app.js";

const PORT = Number(process.env.PORT || 8793);
const HOST = process.env.HOST || "127.0.0.1";
const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");
const TRUST_PROXY = process.env.TRUST_PROXY !== "0"; // IP клиента берём из X-Real-IP (его ставит nginx)

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, "misdar.db"));
db.exec("PRAGMA journal_mode=WAL");
db.exec("PRAGMA synchronous=NORMAL");
db.exec("PRAGMA busy_timeout=5000");

// Адаптер под API Durable Object SQLite: exec(query, ...bindings) -> { toArray() }
const stmts = new Map();
const sql = {
  exec(query, ...bindings) {
    let st = stmts.get(query);
    if (!st) { st = db.prepare(query); stmts.set(query, st); }
    if (/^\s*(select|with|pragma)/i.test(query)) { const rows = st.all(...bindings); return { toArray: () => rows, one: () => rows[0] }; }
    st.run(...bindings);
    return { toArray: () => [] };
  },
};

const core = new RollCallCore(sql);

const server = http.createServer(async (req, res) => {
  try {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
    const ip = (TRUST_PROXY && (req.headers["x-real-ip"] || String(req.headers["x-forwarded-for"] || "").split(",")[0].trim())) || req.socket.remoteAddress || "0";
    headers.set("CF-Connecting-IP", ip);
    const host = req.headers.host || "localhost";
    const request = new Request("http://" + host + req.url, { method: req.method, headers, body });
    let r = null;
    if (new URL(request.url).pathname.startsWith("/api/")) r = await core.fetch(request);
    else r = handleStatic(request) || new Response("Not found", { status: 404 });
    res.statusCode = r.status;
    const setCookies = r.headers.getSetCookie ? r.headers.getSetCookie() : [];
    r.headers.forEach((v, k) => { if (k.toLowerCase() !== "set-cookie") res.setHeader(k, v); });
    if (setCookies.length) res.setHeader("Set-Cookie", setCookies);
    res.end(Buffer.from(await r.arrayBuffer()));
  } catch (e) {
    console.error(new Date().toISOString(), "error:", e && e.stack || e);
    if (!res.headersSent) { res.statusCode = 500; res.setHeader("Content-Type", "application/json"); }
    res.end(JSON.stringify({ error: "server" }));
  }
});

server.keepAliveTimeout = 65000;
server.listen(PORT, HOST, () => console.log(`misdar listening on http://${HOST}:${PORT}, data: ${DATA_DIR}`));

function shutdown(sig) {
  console.log(`${sig}: shutting down`);
  server.close(() => { try { db.close(); } catch {} process.exit(0); });
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
