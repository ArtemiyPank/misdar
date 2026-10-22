// Точка входа для Cloudflare Workers (вариант без своего сервера).
// Данные живут в Durable Object (SQLite). Для своего сервера см. server.js.

import { DurableObject } from "cloudflare:workers";
import { RollCallCore, handleStatic } from "./app.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      const id = env.ROLLCALL.idFromName("main");
      return env.ROLLCALL.get(id).fetch(request);
    }
    return handleStatic(request) || new Response("Not found", { status: 404 });
  },
};

export class RollCall extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.core = new RollCallCore(ctx.storage.sql);
  }
  fetch(request) {
    return this.core.fetch(request);
  }
}
