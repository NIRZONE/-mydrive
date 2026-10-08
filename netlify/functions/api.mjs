import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const ADMIN_USER = process.env.ADMIN_USER || "nirjon";
const ADMIN_PASS = process.env.ADMIN_PASS || "nirjon";
const NAME = /^[A-Za-z0-9_-]{1,20}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const TIME = /^\d{2}-\d{2}-\d{2}$/;
const MAX_BYTES = 4.5 * 1024 * 1024;

const store = () => getStore({ name: "drive", consistency: "strong" });
const J = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json" } });
const err = (m, s = 400) => J({ error: m }, s);
const hash = (p, salt) => crypto.scryptSync(p, salt, 32).toString("hex");
const mkUser = (pw, role) => { const salt = crypto.randomBytes(16).toString("hex"); return { salt, hash: hash(pw, salt), role, created: Date.now() }; };

async function secret(s) {
  let k = await s.get("secret");
  if (!k) { k = crypto.randomBytes(32).toString("hex"); await s.set("secret", k); }
  return k;
}
async function getUsers(s) {
  let u = await s.get("users", { type: "json" });
  if (!u) { u = { [ADMIN_USER]: mkUser(ADMIN_PASS, "admin") }; await s.setJSON("users", u); }
  return u;
}
async function sign(s, u) {
  const p = Buffer.from(JSON.stringify({ u, exp: Date.now() + 7 * 864e5 })).toString("base64url");
  const sig = crypto.createHmac("sha256", await secret(s)).update(p).digest("base64url");
  return p + "." + sig;
}
async function auth(req, s, url) {
  const h = req.headers.get("authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : url.searchParams.get("t");
  if (!t) return null;
  const [p, sig] = t.split(".");
  if (!p || !sig) return null;
  const good = crypto.createHmac("sha256", await secret(s)).update(p).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let d; try { d = JSON.parse(Buffer.from(p, "base64url").toString()); } catch { return null; }
  if (!d.u || d.exp < Date.now()) return null;
  const users = await getUsers(s);
  const rec = users[d.u];
  return rec ? { username: d.u, role: rec.role } : null;
}
async function metas(s, prefix) {
  const { blobs } = await s.list({ prefix });
  return (await Promise.all(blobs.map((b) => s.get(b.key, { type: "json" })))).filter(Boolean);
}

export default async (req) => {
  const s = store();
  const url = new URL(req.url);
  const [a, b, c] = url.pathname.replace(/^\/api\//, "").split("/").filter(Boolean);
  const m = req.method;
  try {
    if (a === "login" && m === "POST") {
      const { username, password } = await req.json();
      const users = await getUsers(s);
      const u = users[username];
      if (!u || typeof password !== "string") return err("Wrong username or password", 401);
      const ok = crypto.timingSafeEqual(Buffer.from(hash(password, u.salt)), Buffer.from(u.hash));
      if (!ok) return err("Wrong username or password", 401);
      return J({ token: await sign(s, username), user: { username, role: u.role } });
    }

    const me = await auth(req, s, url);
    if (!me) return err("Unauthorized", 401);
    const admin = me.role === "admin";

    if (a === "me") return J({ user: me });

    if (a === "photos" && m === "GET") {
      let list = await metas(s, "meta/");
      if (!admin) list = list.filter((p) => p.owner === me.username);
      return J({ photos: list.sort((x, y) => y.ts - x.ts) });
    }

    if (a === "img" && m === "GET") {
      if (!DAY.test((b || "").slice(0, 10))) return err("Bad id");
      const meta = await s.get(`meta/${b.slice(0, 10)}/${b}`, { type: "json" });
      if (!meta || (!admin && meta.owner !== me.username)) return err("Not found", 404);
      const buf = await s.get("img/" + b, { type: "arrayBuffer" });
      if (!buf) return err("Not found", 404);
      return new Response(buf, { headers: { "content-type": "image/jpeg", "cache-control": "private, max-age=31536000, immutable" } });
    }

    if (a === "upload" && m === "POST") {
      const day = url.searchParams.get("day"), time = url.searchParams.get("time");
      if (!DAY.test(day || "") || !TIME.test(time || "")) return err("Bad date/time");
      const buf = await req.arrayBuffer();
      if (!buf.byteLength || buf.byteLength > MAX_BYTES) return err("Photo too large (max 4.5 MB)", 413);
      const [y, mo, d] = day.split("-").map(Number);
      const base = `${me.username}_${d}-${mo}-${y}_${time}`;
      const used = new Set((await metas(s, `meta/${day}/`)).map((p) => p.name));
      let name = base + ".jpg", i = 2;
      while (used.has(name)) name = `${base}_${i++}.jpg`;
      const id = day + "_" + crypto.randomBytes(6).toString("hex");
      const meta = { id, owner: me.username, name, orig: (url.searchParams.get("orig") || "").slice(0, 120), size: buf.byteLength, day, ts: Date.now() };
      await s.set("img/" + id, buf);
      await s.setJSON(`meta/${day}/${id}`, meta);
      return J({ photo: meta });
    }

    if (a === "photo" && m === "DELETE") {
      if (!DAY.test((b || "").slice(0, 10))) return err("Bad id");
      const key = `meta/${b.slice(0, 10)}/${b}`;
      const meta = await s.get(key, { type: "json" });
      if (!meta) return err("Not found", 404);
      if (!admin && meta.owner !== me.username) return err("Forbidden", 403);
      await s.delete(key); await s.delete("img/" + b);
      return J({ ok: true });
    }

    if (a === "password" && m === "POST") {
      const { old, pw } = await req.json();
      if (!pw || pw.length < 4) return err("Password must be at least 4 characters");
      const users = await getUsers(s);
      if (hash(old || "", users[me.username].salt) !== users[me.username].hash) return err("Current password is wrong", 403);
      users[me.username] = { ...users[me.username], ...mkUser(pw, users[me.username].role), created: users[me.username].created };
      await s.setJSON("users", users);
      return J({ ok: true });
    }

    if (a === "users") {
      if (!admin) return err("Admins only", 403);
      const users = await getUsers(s);
      if (m === "GET") {
        const all = await metas(s, "meta/");
        return J({ users: Object.entries(users).map(([username, u]) => {
          const mine = all.filter((p) => p.owner === username);
          return { username, role: u.role, photos: mine.length, size: mine.reduce((t, p) => t + p.size, 0), created: u.created };
        }) });
      }
      if (m === "POST" && !b) {
        const { username, password } = await req.json();
        if (!NAME.test(username || "")) return err("Username: letters, numbers, - or _ (max 20)");
        if (!password || password.length < 4) return err("Password must be at least 4 characters");
        if (users[username]) return err("That username already exists", 409);
        users[username] = mkUser(password, "user");
        await s.setJSON("users", users);
        return J({ ok: true });
      }
      if (m === "POST" && b && c === "password") {
        const { pw } = await req.json();
        if (!users[b]) return err("No such user", 404);
        if (!pw || pw.length < 4) return err("Password must be at least 4 characters");
        users[b] = { ...mkUser(pw, users[b].role), created: users[b].created };
        await s.setJSON("users", users);
        return J({ ok: true });
      }
      if (m === "DELETE" && b) {
        if (!users[b]) return err("No such user", 404);
        if (b === me.username) return err("You can't delete yourself", 400);
        delete users[b];
        await s.setJSON("users", users);
        return J({ ok: true });
      }
    }
    return err("Not found", 404);
  } catch (e) {
    return err("Server error: " + (e && e.message || e), 500);
  }
};

export const config = { path: "/api/*" };
