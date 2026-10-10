/**
 * Coursatk API — protected backend
 * - Student codes (7-digit) + devices + sessions in Firebase RTDB
 * - Admin panel API (users, permissions, sections, subject IDs)
 * - Stream-Weave key unwrap + AES-128 segment decrypt (upstream token NEVER leaves server)
 * - All student/catalog/stream routes require valid session token
 */
import express from "express";
import cors from "cors";
import compression from "compression";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "data");
const MEDIA_DIR = path.join(DATA_DIR, "media");
try { fs.mkdirSync(MEDIA_DIR, { recursive: true }); } catch {}
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: false }));
app.use(express.json({ limit: "20mb" }));
app.use(compression());

// ═══════════════════════════════════════════════════════════
// Rate limit — strict, no bypass via X-Forwarded-For spoof alone
// ═══════════════════════════════════════════════════════════
const rateBuckets = new Map();
const banBuckets = new Map(); // temporary IP bans

function clientIp(req) {
  // trust proxy is on — Express already resolves req.ip from X-Forwarded-For safely when set
  const ip = req.ip || req.socket?.remoteAddress || "unknown";
  return String(ip).replace(/^::ffff:/, "");
}

function rateLimit(options = {}) {
  const windowMs = options.windowMs || 60_000;
  const max = options.max || 40;
  const scope = options.scope || "global";
  const banAfter = options.banAfter || 0; // consecutive 429s before short ban
  const banMs = options.banMs || 5 * 60_000;
  return (req, res, next) => {
    const ip = clientIp(req);
    const banKey = ip + ":ban:" + scope;
    const bannedUntil = banBuckets.get(banKey) || 0;
    if (bannedUntil > Date.now()) {
      const sec = Math.ceil((bannedUntil - Date.now()) / 1000);
      res.setHeader("Retry-After", String(sec));
      return res.status(429).json({
        success: false,
        message: `محظور مؤقتًا — حاول بعد ${sec} ثانية`
      });
    }
    const key = ip + ":" + scope;
    const t = Date.now();
    let b = rateBuckets.get(key);
    if (!b || t > b.resetAt) {
      b = { count: 0, resetAt: t + windowMs, hits429: 0 };
      rateBuckets.set(key, b);
    }
    b.count += 1;
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max - b.count)));
    res.setHeader("X-RateLimit-Reset", String(Math.ceil(b.resetAt / 1000)));
    if (b.count > max) {
      b.hits429 = (b.hits429 || 0) + 1;
      if (banAfter > 0 && b.hits429 >= banAfter) {
        banBuckets.set(banKey, Date.now() + banMs);
      }
      const sec = Math.ceil((b.resetAt - t) / 1000);
      res.setHeader("Retry-After", String(Math.max(1, sec)));
      return res.status(429).json({
        success: false,
        message: "طلبات كثيرة — حاول بعد قليل"
      });
    }
    next();
  };
}

setInterval(() => {
  const t = Date.now();
  for (const [k, b] of rateBuckets) {
    if (t > b.resetAt) rateBuckets.delete(k);
  }
  for (const [k, until] of banBuckets) {
    if (t > until) banBuckets.delete(k);
  }
}, 30_000).unref();


// ═══════════════════════════════════════════════════════════
// Login fail lock — 5 wrong tries → 15 min cooldown (per IP+code/user)
// ═══════════════════════════════════════════════════════════
const loginFails = new Map(); // key -> { count, lockedUntil }

function loginFailKey(kind, ip, id) {
  return kind + ":" + ip + ":" + String(id || "").toLowerCase();
}

function checkLoginLock(kind, ip, id) {
  const key = loginFailKey(kind, ip, id);
  const row = loginFails.get(key);
  if (!row) return null;
  if (row.lockedUntil && Date.now() < row.lockedUntil) {
    const sec = Math.ceil((row.lockedUntil - Date.now()) / 1000);
    return { locked: true, sec, remaining: 0 };
  }
  if (row.lockedUntil && Date.now() >= row.lockedUntil) {
    loginFails.delete(key);
    return null;
  }
  return { locked: false, remaining: Math.max(0, 5 - (row.count || 0)) };
}

function recordLoginFail(kind, ip, id) {
  const key = loginFailKey(kind, ip, id);
  const row = loginFails.get(key) || { count: 0, lockedUntil: 0 };
  row.count = (row.count || 0) + 1;
  if (row.count >= 5) {
    row.lockedUntil = Date.now() + 15 * 60_000; // 15 minutes
    row.count = 0;
  }
  loginFails.set(key, row);
  if (row.lockedUntil && Date.now() < row.lockedUntil) {
    const sec = Math.ceil((row.lockedUntil - Date.now()) / 1000);
    return { locked: true, sec };
  }
  return { locked: false, remaining: Math.max(0, 5 - row.count) };
}

function clearLoginFail(kind, ip, id) {
  loginFails.delete(loginFailKey(kind, ip, id));
}

setInterval(() => {
  const t = Date.now();
  for (const [k, row] of loginFails) {
    if (row.lockedUntil && t > row.lockedUntil + 60_000) loginFails.delete(k);
  }
}, 60_000).unref();


// ═══════════════════════════════════════════════════════════
// CONFIG (in-code — no Railway vars required for core secrets)
// ═══════════════════════════════════════════════════════════
const CONFIG = {
  PORT: Number(process.env.PORT || 3000),
  // Upstream Coursatk — token loaded from runtime/Firebase/env (never exposed to client)
  COURSATK_API: "https://api.coursatk.online/api/v1",
  COURSATK_TOKEN: "", // set via admin panel or env COURSATK_TOKEN
  DEFAULT_YEAR_ID: 4,
  STREAM_HOSTS: [
    "api.coursatk.online",
    "stream-weave.com",
    "floravon.online",
    "c-cdn.online"
  ],
  STREAM_ORIGIN: "https://coursatk.online",
  STREAM_REFERER: "https://coursatk.online/",
  STREAM_X_REQUESTED_WITH: "com.mycompany.app.soulbrowser",
  STREAM_UA:
    "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/153.0.0.0 Mobile Safari/537.36",
  PLAYER_JS: "https://player.stream-weave.com/assets/player.js?v=1.1.1",
  // Firebase Realtime Database (NOT Firestore)
  FIREBASE: "https://dr-gamal-357a2-default-rtdb.firebaseio.com",
  // Bootstrap admin (always valid even if Firebase empty)
  BOOTSTRAP_ADMIN: {
    username: "Hema",
    // password set below — hashed at boot
    passwordHash: "",
    passwordPlain: "ibrahim@2009*#",
    permissions: {
      students_create: true,
      students_edit: true,
      students_delete: true,
      students_view: true,
      devices_kick: true,
      sections_manage: true,
      admins_manage: true
    }
  },
  // Session TTL
  STUDENT_SESSION_MS: 7 * 24 * 3600 * 1000, // 7 days max (also capped by code expiry)
  ADMIN_SESSION_MS: 12 * 3600 * 1000, // 12h
  STREAM_SESSION_MS: 15 * 60 * 1000,
  MAX_PROXY_BYTES: 12 * 1024 * 1024,
  CODE_TYPES: {
    trial: { label: "تجربة", ms: 1 * 3600 * 1000 },
    month: { label: "شهر", ms: 30 * 24 * 3600 * 1000 },
    term: { label: "ترم (6 شهور)", ms: 180 * 24 * 3600 * 1000 },
    year: { label: "سنة (12 شهر)", ms: 365 * 24 * 3600 * 1000 }
  }
};



// ═══════════════════════════════════════════════════════════
// Runtime config (file on disk + Firebase site settings)
// Firebase URL / token NOT hardcoded — admin sets them in panel
// ═══════════════════════════════════════════════════════════
const RUNTIME_PATH = path.join(__dirname, "data", "runtime.json");

const runtime = {
  firebaseUrl: (process.env.FIREBASE_URL || "https://dr-gamal-357a2-default-rtdb.firebaseio.com").replace(/\/$/, ""),
  coursatkToken: process.env.COURSATK_TOKEN || "",
  siteName: "كورساتك",
  packages: [
    { id: "month", name: "باقة الشهر — 30 يوم", price: 200, days: 30, hours: 0, active: true },
    { id: "term", name: "باقة الترم — لحد شهر 1", price: 500, days: 90, hours: 0, active: true },
    { id: "year", name: "باقة السنة — السنة كلها بالمراجعات النهائية", price: 900, days: 365, hours: 0, active: true }
  ],
  agents: [] // { id, name, telegram, active }
};

function ensureDataDir() {
  const dir = path.dirname(RUNTIME_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function loadRuntimeFile() {
  try {
    if (!fs.existsSync(RUNTIME_PATH)) return;
    const raw = JSON.parse(fs.readFileSync(RUNTIME_PATH, "utf8"));
    if (raw.firebaseUrl) runtime.firebaseUrl = String(raw.firebaseUrl).replace(/\/$/, "");
    if (raw.coursatkToken) runtime.coursatkToken = String(raw.coursatkToken);
    if (raw.siteName) runtime.siteName = String(raw.siteName);
    if (Array.isArray(raw.packages)) runtime.packages = raw.packages;
    if (Array.isArray(raw.agents)) runtime.agents = raw.agents;
    if (raw.storageBucket) runtime.storageBucket = String(raw.storageBucket);
    console.log("[API] runtime.json loaded");
  } catch (e) {
    console.warn("[API] runtime load:", e.message);
  }
}

function saveRuntimeFile() {
  ensureDataDir();
  const out = {
    firebaseUrl: runtime.firebaseUrl,
    coursatkToken: runtime.coursatkToken,
    siteName: runtime.siteName,
    packages: runtime.packages,
    agents: runtime.agents,
    updatedAt: Date.now()
  };
  fs.writeFileSync(RUNTIME_PATH, JSON.stringify(out, null, 2), "utf8");
}

function getFirebaseUrl() {
  return (
    runtime.firebaseUrl ||
    process.env.FIREBASE_URL ||
    CONFIG.FIREBASE ||
    "https://dr-gamal-357a2-default-rtdb.firebaseio.com"
  ).replace(/\/$/, "");
}

function getCoursatkTokenSync() {
  return runtime.coursatkToken || process.env.COURSATK_TOKEN || CONFIG.COURSATK_TOKEN || "";
}

loadRuntimeFile();
// apply token into CONFIG for existing helpers
CONFIG.COURSATK_TOKEN = getCoursatkTokenSync();
CONFIG.FIREBASE = getFirebaseUrl();
console.log("[API] Firebase:", getFirebaseUrl() ? "configured" : "NOT set — bootstrap admin can still login");
console.log("[API] Token:", getCoursatkTokenSync() ? "set" : "missing");

function packageDurationMs(pkg) {
  if (!pkg) return 0;
  const days = Number(pkg.days || 0);
  const hours = Number(pkg.hours || 0);
  return (days * 24 + hours) * 3600 * 1000;
}


// Canonical subject IDs per section (fallback if Firebase section missing)
const SECTION_CATALOG = {
  scientific_sciences: {
    name: "علمي علوم",
    yearId: 4,
    subjectIds: [57, 58, 59, 60, 61]
  },
  scientific_math: {
    name: "علمي رياضة",
    yearId: 4,
    subjectIds: [57, 58, 59, 60, 65]
  },
  literary: {
    name: "أدبي",
    yearId: 4,
    subjectIds: [57, 58, 62, 63, 64]
  },
  "بكالوريا": {
    name: "بكالوريا",
    yearId: 4,
    subjectIds: [57, 58, 62, 63, 64]
  }
};

/** Normalize section key from admin/UI variants */
function normalizeSection(raw) {
  if (raw == null || raw === "") return null;
  const s = String(raw).trim();
  if (!s) return null;
  const lower = s.toLowerCase().replace(/\s+/g, "_");
  const map = {
    scientific_sciences: "scientific_sciences",
    scientific_math: "scientific_math",
    literary: "literary",
    "علمي_علوم": "scientific_sciences",
    "علمي_رياضة": "scientific_math",
    "علمي_رياضه": "scientific_math",
    "ادبي": "literary",
    "أدبي": "literary",
    "باكلوريا": "بكالوريا",
    "بكالوريا": "بكالوريا",
    bakaloria: "بكالوريا",
    baccalaureate: "بكالوريا",
    "أزهري": "azhari",
    azhari: "azhari",
    sciences: "scientific_sciences",
    math: "scientific_math",
    science: "scientific_sciences"
  };
  if (map[s]) return map[s];
  if (map[lower]) return map[lower];
  if (s.includes("علوم") && !s.includes("رياض")) return "scientific_sciences";
  if (s.includes("رياض")) return "scientific_math";
  if (s.includes("أدب") || s.includes("ادب")) return "literary";
  return s;
}

/** Resolve section config: Firebase first, then hardcoded catalog */
async function resolveSection(sectionRaw) {
  const id = normalizeSection(sectionRaw);
  if (!id) return null;
  try {
    if (getFirebaseUrl()) {
      const sec = await fbGetCached(`sections/${id}`, 60_000);
      if (sec && Array.isArray(sec.subjectIds) && sec.subjectIds.length) {
        return {
          id,
          name: sec.name || (SECTION_CATALOG[id] && SECTION_CATALOG[id].name) || id,
          yearId: Number(sec.yearId) || (SECTION_CATALOG[id] && SECTION_CATALOG[id].yearId) || CONFIG.DEFAULT_YEAR_ID,
          subjectIds: sec.subjectIds.map(Number).filter((n) => !Number.isNaN(n))
        };
      }
    }
  } catch (e) {
    console.warn("[section]", e.message);
  }
  const def = SECTION_CATALOG[id];
  if (def) {
    return { id, name: def.name, yearId: def.yearId, subjectIds: [...def.subjectIds] };
  }
  return { id, name: id, yearId: CONFIG.DEFAULT_YEAR_ID, subjectIds: [] };
}


function resolveDurationMs(body) {
  // custom days takes priority
  if (body?.days != null && body.days !== "") {
    const d = Number(body.days);
    if (!Number.isNaN(d) && d > 0 && d <= 3650) return Math.round(d * 24 * 3600 * 1000);
  }
  if (body?.hours != null && Number(body.hours) > 0) {
    return Math.round(Number(body.hours) * 3600 * 1000);
  }
  const type = String(body?.type || "month");
  // from runtime packages
  const pkg = (runtime.packages || []).find((p) => p.id === type);
  if (pkg) {
    const ms = packageDurationMs(pkg);
    if (ms > 0) return ms;
  }
  if (CONFIG.CODE_TYPES[type]) return CONFIG.CODE_TYPES[type].ms;
  return CONFIG.CODE_TYPES.month.ms;
}


// ═══════════════════════════════════════════════════════════
// In-memory TTL cache — يقلل ضغط Firebase والـ upstream مع زيادة المستخدمين
// ═══════════════════════════════════════════════════════════
const memCache = new Map();

function cacheGet(key) {
  const e = memCache.get(key);
  if (!e) return null;
  if (Date.now() > e.exp) {
    memCache.delete(key);
    return null;
  }
  return e.val;
}
function cacheSet(key, val, ttlMs = 30_000) {
  memCache.set(key, { val, exp: Date.now() + ttlMs });
  return val;
}
function cacheDel(prefix) {
  for (const k of memCache.keys()) {
    if (k === prefix || k.startsWith(prefix)) memCache.delete(k);
  }
}
setInterval(() => {
  const t = Date.now();
  for (const [k, e] of memCache) {
    if (t > e.exp) memCache.delete(k);
  }
}, 60_000).unref();

// ═══════════════════════════════════════════════════════════
// Crypto helpers
// ═══════════════════════════════════════════════════════════
function scryptHash(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32, {
    N: 16384,
    r: 8,
    p: 1
  });
  return `scrypt$16384$8$1$${salt.toString("hex")}$${hash.toString("hex")}`;
}

function scryptVerify(password, stored) {
  try {
    if (stored.startsWith("scrypt$")) {
      const parts = stored.split("$");
      const salt = parts[4];
      const expect = parts[5];
      const hash = crypto.scryptSync(password, Buffer.from(salt, "hex"), 32, {
        N: 16384,
        r: 8,
        p: 1
      });
      return crypto.timingSafeEqual(Buffer.from(expect, "hex"), hash);
    }
    // plain fallback (bootstrap migration)
    return password === stored;
  } catch {
    return false;
  }
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function randomCode9() {
  // 1000000 – 9999999
  return String(Math.floor(1000000 + Math.random() * 9000000));
}

function now() {
  return Date.now();
}

// ═══════════════════════════════════════════════════════════
// Firebase RTDB REST
// ═══════════════════════════════════════════════════════════
async function fbGetCached(p, ttlMs = 20_000) {
  const key = "fb:" + p;
  const hit = cacheGet(key);
  if (hit !== null) return hit;
  const val = await fbGet(p);
  cacheSet(key, val, ttlMs);
  return val;
}

async function fbGet(p) {
  const base = getFirebaseUrl();
  if (!base) throw new Error("Firebase غير مضبوط — أدخله من لوحة التحكم");
  const r = await fetch(`${base}/${p}.json`, {
    headers: { Accept: "application/json" },
    cache: "no-store"
  });
  const text = await r.text();
  if (text.trim().startsWith("<")) {
    throw new Error(
      "رابط Firebase غلط أو قاعدة Realtime Database مش متإنشاءة. من Console → Build → Realtime Database → Create (مش Firestore)"
    );
  }
  if (!r.ok) {
    let msg = text.slice(0, 200);
    try { msg = JSON.parse(text).error || msg; } catch {}
    throw new Error("Firebase GET فشل: " + msg);
  }
  if (!text || text === "null") return null;
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Firebase رجّع رد مش JSON");
  }
}

async function fbSet(p, data) {
  const base = getFirebaseUrl();
  if (!base) throw new Error("Firebase غير مضبوط — أدخله من لوحة التحكم");
  const r = await fetch(`${base}/${p}.json`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(data)
  });
  const text = await r.text();
  if (text.trim().startsWith("<")) {
    throw new Error(
      "قاعدة Realtime Database مش متإنشاءة أو الرابط غلط (المشروع الحالي فيه Firestore فقط — أنشئ Realtime Database)"
    );
  }
  if (!r.ok) {
    let msg = text.slice(0, 200);
    try { msg = JSON.parse(text).error || msg; } catch {}
    throw new Error("Firebase SET فشل: " + msg);
  }
  try { return text ? JSON.parse(text) : null; } catch { return null; }
}

async function fbPatch(p, data) {
  const base = getFirebaseUrl();
  if (!base) throw new Error("Firebase غير مضبوط — أدخله من لوحة التحكم");
  const r = await fetch(`${base}/${p}.json`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(data)
  });
  const text = await r.text();
  if (text.trim().startsWith("<")) {
    throw new Error("Realtime Database مش جاهزة — أنشئها من Firebase Console");
  }
  if (!r.ok) {
    let msg = text.slice(0, 200);
    try { msg = JSON.parse(text).error || msg; } catch {}
    throw new Error("Firebase PATCH فشل: " + msg);
  }
  try { return text ? JSON.parse(text) : null; } catch { return null; }
}


async function fbDelete(p) {
  const base = getFirebaseUrl();
  if (!base) throw new Error("Firebase غير مضبوط — أدخله من لوحة التحكم");
  const r = await fetch(`${base}/${p}.json`, { method: "DELETE" });
  if (!r.ok) throw new Error(`Firebase DELETE ${p} → ${r.status}`);
  return true;
}

// Runtime config from Firebase (overrides in-code defaults)
let cachedCoursatkToken = null;
let cachedTokenAt = 0;
async function getStorageBucket() {
  if (runtime.storageBucket) return String(runtime.storageBucket).trim();
  if (process.env.FIREBASE_STORAGE_BUCKET) return process.env.FIREBASE_STORAGE_BUCKET.trim();
  const u = getFirebaseUrl() || "";
  const m = u.match(/https?:\/\/([^.]+)-default-rtdb/i);
  if (m) return m[1] + ".appspot.com";
  return "dr-gamal-357a2.appspot.com";
}

function getCoursatkToken() {
  // priority: runtime file → env (Firebase async load happens separately)
  if (runtime.coursatkToken) return runtime.coursatkToken;
  return process.env.COURSATK_TOKEN || CONFIG.COURSATK_TOKEN || "";
}

async function refreshCoursatkTokenFromFb() {
  try {
    const remote = await fbGet("config/coursatkToken");
    if (typeof remote === "string" && remote.length > 20) {
      runtime.coursatkToken = remote;
      CONFIG.COURSATK_TOKEN = remote;
      return remote;
    }
  } catch {}
  return getCoursatkToken();
}


// ═══════════════════════════════════════════════════════════
// In-memory session caches (source of truth also in Firebase)
// ═══════════════════════════════════════════════════════════
const studentSessions = new Map(); // token -> session
const adminSessions = new Map();
const streamSessions = new Map();

function jsonError(res, status, message) {
  return res.status(status).json({ success: false, message });
}

function getBearer(req) {
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) return h.slice(7).trim();
  const xt = req.headers["x-session-token"];
  if (xt) return String(xt).trim();
  if (req.query && req.query.token) return String(req.query.token).trim();
  return "";
}

// ── Student auth middleware ──
async function requireStudent(req, res, next) {
  try {
    const token = getBearer(req);
    if (!token) return jsonError(res, 401, "مطلوب تسجيل الدخول");

    let sess = studentSessions.get(token);
    if (!sess) {
      const remote = await fbGet(`sessions/${token}`);
      if (!remote) return jsonError(res, 401, "جلسة غير صالحة");
      sess = remote;
      studentSessions.set(token, sess);
    }

    if (sess.expiresAt && now() > sess.expiresAt) {
      studentSessions.delete(token);
      try { await fbDelete(`sessions/${token}`); } catch {}
      return jsonError(res, 401, "انتهت صلاحية الجلسة");
    }

    // Validate student still exists & active & not expired
    const student = await fbGet(`students/${sess.code}`);
    if (!student || student.active === false) {
      studentSessions.delete(token);
      return jsonError(res, 401, "الحساب غير موجود أو موقوف");
    }
    if (student.expiresAt && now() > student.expiresAt) {
      return jsonError(res, 403, "انتهت صلاحية كود الاشتراك");
    }

    // Device still registered?
    const devices = student.devices || {};
    if (sess.deviceId && !devices[sess.deviceId]) {
      studentSessions.delete(token);
      try { await fbDelete(`sessions/${token}`); } catch {}
      return jsonError(res, 401, "تم تسجيل خروج هذا الجهاز من لوحة التحكم");
    }

    // CRITICAL: student record in Firebase is keyed by code but does not store code field
    // Without attaching code, all students shared messages/undefined
    req.student = { ...student, code: String(sess.code) };
    req.session = sess;
    req.sessionToken = token;
    next();
  } catch (e) {
    console.error("[auth student]", e.message);
    return jsonError(res, 500, "خطأ في التحقق من الجلسة");
  }
}

// ── Admin auth middleware ──
function requireAdmin(permission) {
  return async (req, res, next) => {
    try {
      const token = getBearer(req);
      if (!token) return jsonError(res, 401, "مطلوب دخول الأدمن");

      let sess = adminSessions.get(token);
      if (!sess) {
        if (getFirebaseUrl()) {
          try {
            const remote = await fbGet(`admin_sessions/${token}`);
            if (remote) {
              sess = remote;
              adminSessions.set(token, sess);
            }
          } catch (err) {
            console.warn("[requireAdmin] fb session:", err.message);
          }
        }
        if (!sess) return jsonError(res, 401, "جلسة أدمن غير صالحة");
      }

      if (sess.expiresAt && now() > sess.expiresAt) {
        adminSessions.delete(token);
        try { await fbDelete(`admin_sessions/${token}`); } catch {}
        return jsonError(res, 401, "انتهت جلسة الأدمن");
      }

      // Load admin record
      let admin = null;
      if (sess.username === CONFIG.BOOTSTRAP_ADMIN.username) {
        admin = {
          username: CONFIG.BOOTSTRAP_ADMIN.username,
          permissions: CONFIG.BOOTSTRAP_ADMIN.permissions,
          bootstrap: true
        };
      } else {
        admin = await fbGet(`admins/${sess.adminId}`);
        if (!admin || admin.active === false) {
          return jsonError(res, 401, "حساب الأدمن غير موجود");
        }
      }

      if (permission) {
        const perms = admin.permissions || {};
        if (!perms[permission] && !perms.all) {
          return jsonError(res, 403, `لا تملك صلاحية: ${permission}`);
        }
      }

      req.admin = admin;
      req.adminSession = sess;
      req.adminToken = token;
      next();
    } catch (e) {
      console.error("[auth admin]", e.message);
      return jsonError(res, 500, "خطأ في تحقق الأدمن");
    }
  };
}

// ═══════════════════════════════════════════════════════════
// Stream-Weave decrypt (server-only)
// ═══════════════════════════════════════════════════════════
let decryptPlaybackKeyFn = null;

async function loadDecryptionUtils() {
  const cachePath = path.join(__dirname, "player.stream-weave.cache.js");
  let source = null;
  try {
    if (fs.existsSync(cachePath)) source = fs.readFileSync(cachePath, "utf8");
  } catch {}
  if (!source) {
    console.log("[crypto] fetching player.js…");
    const r = await fetch(CONFIG.PLAYER_JS, {
      headers: { "User-Agent": "Mozilla/5.0", Accept: "*/*" }
    });
    if (!r.ok) throw new Error(`player.js HTTP ${r.status}`);
    source = await r.text();
    try { fs.writeFileSync(cachePath, source); } catch {}
  }
  const { webcrypto } = crypto;
  const sandbox = {
    window: {}, self: {}, globalThis: {}, global: {},
    console: { log() {}, warn() {}, error() {}, info() {} },
    crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer,
    atob: (s) => Buffer.from(s, "base64").toString("binary"),
    btoa: (s) => Buffer.from(s, "binary").toString("base64"),
    setTimeout, clearTimeout, setInterval, clearInterval,
    Promise, Error, Object, Array, String, Number, Boolean, Math, JSON, Date,
    Map, Set, WeakMap, Symbol, Proxy, Reflect,
    document: {
      createElement: () => ({ style: {}, setAttribute() {}, appendChild() {}, remove() {} }),
      head: { appendChild() {} }, body: { appendChild() {} },
      querySelector: () => null, addEventListener() {}
    },
    navigator: { userAgent: "Node" },
    location: { href: "https://coursatk.online/" },
    HTMLElement: class {}, HTMLVideoElement: class {}, MediaSource: class {},
    URL: { createObjectURL: () => "blob:x", revokeObjectURL() {} },
    Blob: class { constructor(p) { this.p = p; } },
    fetch: async () => ({ ok: false }),
    XMLHttpRequest: class { open() {} send() {} setRequestHeader() {} }
  };
  sandbox.window = sandbox; sandbox.self = sandbox;
  sandbox.globalThis = sandbox; sandbox.global = sandbox;
  vm.runInNewContext(source, sandbox, { timeout: 8000 });
  const du = sandbox.DecryptionUtils;
  if (!du?.decryptPlaybackKey) throw new Error("DecryptionUtils missing");
  decryptPlaybackKeyFn = du.decryptPlaybackKey.bind(du);
  console.log("[crypto] ready");
}

async function unwrapKey(wrappedBuf, videoId) {
  if (!decryptPlaybackKeyFn) throw new Error("crypto not loaded");
  const wrapped = Buffer.isBuffer(wrappedBuf)
    ? new Uint8Array(wrappedBuf)
    : new Uint8Array(wrappedBuf);
  if (wrapped.byteLength === 16) return Buffer.from(wrapped);
  const result = await decryptPlaybackKeyFn(wrapped, String(videoId));
  const key = result?.key;
  if (!key) throw new Error("empty key");
  const aes = Buffer.isBuffer(key)
    ? key
    : key instanceof ArrayBuffer
      ? Buffer.from(key)
      : Buffer.from(key.buffer || key, key.byteOffset || 0, key.byteLength || key.length);
  if (aes.length !== 16) throw new Error(`key len ${aes.length}`);
  return aes;
}

function decryptSegment(encrypted, key, iv) {
  const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

function parseIvHex(hex) {
  const h = String(hex || "").replace(/^0x/i, "").trim();
  if (!/^[0-9a-fA-F]{32}$/.test(h)) return null;
  return Buffer.from(h, "hex");
}

function ivFromMediaSequence(seq) {
  const iv = Buffer.alloc(16, 0);
  iv.writeUInt32BE(Number(seq) >>> 0, 12);
  return iv;
}

// Upstream helpers (token never exposed)
async function upstreamHeaders(extra = {}) {
  const tok = await getCoursatkToken();
  return {
    Authorization: `Bearer ${tok}`,
    Accept: "application/json",
    ...extra
  };
}

async function upstreamJson(apiPath, options = {}) {
  const r = await fetch(`${CONFIG.COURSATK_API}${apiPath}`, {
    ...options,
    headers: await upstreamHeaders(options.headers || {})
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch {
    throw new Error(`Upstream non-JSON (${r.status})`);
  }
  if (!r.ok) throw new Error(data?.message || `Upstream HTTP ${r.status}`);
  return data;
}

function allowedStreamUrl(raw, session = null) {
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:") return false;
    const hosts = new Set(CONFIG.STREAM_HOSTS);
    if (session?.allowedHosts) for (const h of session.allowedHosts) hosts.add(h);
    if (session?.streamUrl) {
      try { hosts.add(new URL(session.streamUrl).hostname); } catch {}
    }
    return [...hosts].some(h => u.hostname === h || u.hostname.endsWith("." + h));
  } catch {
    return false;
  }
}

async function streamFetch(session, url, extra = {}, clientHeaders = null) {
  if (!allowedStreamUrl(url, session)) throw new Error(`URL غير مسموح: ${url}`);
  const ch = clientHeaders || {};
  const headers = {
    Authorization: `Bearer ${session.token}`,
    Accept: "*/*",
    "Cache-Control": "no-cache",
    Origin: CONFIG.STREAM_ORIGIN,
    Referer: CONFIG.STREAM_REFERER,
    "X-Requested-With": CONFIG.STREAM_X_REQUESTED_WITH,
    "User-Agent": ch["user-agent"] || CONFIG.STREAM_UA
  };
  for (const name of [
    "sec-ch-ua-platform", "sec-ch-ua", "sec-ch-ua-mobile",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-language"
  ]) {
    if (ch[name]) headers[name] = ch[name];
  }
  for (const [k, v] of Object.entries(extra || {})) {
    if (v != null && v !== "") headers[k] = v;
  }
  return fetch(url, { headers, cache: "no-store" });
}

// ═══════════════════════════════════════════════════════════
// PUBLIC (no auth)
// ═══════════════════════════════════════════════════════════
// Global: soft only (prevents total abuse, won't block normal admin/import)
app.use(rateLimit({ max: 300, windowMs: 60_000, scope: "global" }));

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    service: "coursatk-protected-api",
    cryptoReady: Boolean(decryptPlaybackKeyFn),
    decryptSegments: true,
    now: new Date().toISOString()
  });
});

app.get("/api/public/code-types", (_req, res) => {
  const types = {};
  for (const [k, v] of Object.entries(CONFIG.CODE_TYPES)) {
    types[k] = { label: v.label, durationMs: v.ms };
  }
  // merge runtime packages
  for (const pkg of runtime.packages || []) {
    if (!pkg.active && pkg.active !== undefined) continue;
    types[pkg.id] = {
      label: pkg.name || pkg.id,
      durationMs: packageDurationMs(pkg),
      price: pkg.price ?? null,
      days: pkg.days || 0
    };
  }
  res.json({ success: true, data: types });
});

/** Public site info for frontend: packages + subscription agents (no secrets) */
app.get("/api/public/site", rateLimit({ max: 120, windowMs: 60_000, scope: "public-site" }), (_req, res) => {
  const packages = (runtime.packages || [])
    .filter((p) => p.active !== false)
    .map((p) => ({
      id: p.id,
      name: p.name,
      price: p.price ?? 0,
      days: p.days || 0,
      hours: p.hours || 0
    }));
  const agents = (runtime.agents || [])
    .filter((a) => a.active !== false)
    .map((a) => ({
      id: a.id,
      name: a.name,
      telegram: a.telegram || ""
    }));
  res.json({
    success: true,
    data: {
      siteName: runtime.siteName || "كورساتك",
      packages,
      agents,
      firebaseConfigured: Boolean(getFirebaseUrl()),
      tokenConfigured: Boolean(getCoursatkTokenSync())
    }
  });
});

// ═══════════════════════════════════════════════════════════
// STUDENT AUTH
// ═══════════════════════════════════════════════════════════
/**
 * POST /api/auth/login
 * body: { code: "1234567", deviceId: "uuid", deviceName?: "Chrome" }
 */
app.post("/api/auth/login", rateLimit({ max: 30, windowMs: 60_000, scope: "student-login" }), async (req, res) => {
  try {
    const code = String(req.body?.code || "").trim();
    const deviceId = String(req.body?.deviceId || "").trim();
    const deviceName = String(req.body?.deviceName || "Unknown").slice(0, 80);
    const ip = clientIp(req);

    if (!/^\d{9}$/.test(code)) {
      return jsonError(res, 400, "الكود يجب أن يكون 9 أرقام");
    }
    if (!deviceId || deviceId.length < 8) {
      return jsonError(res, 400, "deviceId مطلوب");
    }

    const lock = checkLoginLock("student", ip, code);
    if (lock && lock.locked) {
      res.setHeader("Retry-After", String(lock.sec));
      return jsonError(res, 429, `محاولات خاطئة كثيرة — حاول بعد ${Math.ceil(lock.sec / 60)} دقيقة`);
    }

    const student = await fbGet(`students/${code}`);
    if (!student || student.active === false) {
      const fail = recordLoginFail("student", ip, code);
      if (fail.locked) {
        res.setHeader("Retry-After", String(fail.sec));
        return jsonError(res, 429, `محاولات خاطئة كثيرة — حاول بعد 15 دقيقة`);
      }
      return jsonError(res, 401, `كود غير صحيح أو موقوف (متبقي ${fail.remaining} محاولات)`);
    }

    // Activate subscription on FIRST login only
    if (!student.activatedAt) {
      const duration =
        Number(student.durationMs) > 0
          ? Number(student.durationMs)
          : resolveDurationMs({
              type: student.type,
              days: student.days
            });
      if (!duration || duration <= 0) {
        return jsonError(res, 400, "مدة الاشتراك غير محددة لهذا الكود");
      }
      const activatedAt = now();
      const expiresAt = activatedAt + duration;
      await fbPatch(`students/${code}`, {
        activatedAt,
        expiresAt,
        durationMs: duration
      });
      student.activatedAt = activatedAt;
      student.expiresAt = expiresAt;
      student.durationMs = duration;
      console.log("[auth] activated code", code, "until", new Date(expiresAt).toISOString());
    }

    if (student.expiresAt && now() > student.expiresAt) {
      return jsonError(res, 403, "انتهت صلاحية الاشتراك");
    }

    const devices = student.devices || {};
    // reject banned devices
    const bannedMap = student.bannedDevices || {};
    if (deviceId && bannedMap[deviceId]) {
      return jsonError(res, 403, "هذا الجهاز محظور على هذا الكود");
    }

    const maxDevices = Number(student.maxDevices || 1);

    if (!devices[deviceId]) {
      const activeCount = Object.keys(devices).length;
      if (activeCount >= maxDevices) {
        return jsonError(
          res,
          403,
          `تم بلوغ الحد الأقصى للأجهزة (${maxDevices}). اطلب من الأدمن حذف جهاز.`
        );
      }
      devices[deviceId] = {
        name: deviceName,
        addedAt: now(),
        lastSeen: now()
      };
      await fbSet(`students/${code}/devices`, devices);
    } else {
      devices[deviceId].lastSeen = now();
      devices[deviceId].name = deviceName || devices[deviceId].name;
      await fbSet(`students/${code}/devices/${deviceId}`, devices[deviceId]);
    }

    const sessionTtl = Math.min(
      CONFIG.STUDENT_SESSION_MS,
      Math.max(60_000, (student.expiresAt || now() + CONFIG.STUDENT_SESSION_MS) - now())
    );
    const token = randomToken(32);
    const sess = {
      token,
      code,
      deviceId,
      name: student.name,
      section: student.section || null,
      createdAt: now(),
      expiresAt: now() + sessionTtl
    };
    studentSessions.set(token, sess);
    try { await fbSet(`sessions/${token}`, sess); } catch (e) { console.warn("[login] session fb:", e.message); }
    clearLoginFail("student", ip, code);

    // Resolve subject IDs for section (hardcoded fallback + Firebase)
    let subjectIds = [];
    let yearId = CONFIG.DEFAULT_YEAR_ID;
    const secInfo = await resolveSection(student.section);
    if (secInfo) {
      subjectIds = secInfo.subjectIds || [];
      yearId = secInfo.yearId || yearId;
      // normalize stored section key
      if (secInfo.id && student.section !== secInfo.id) {
        try { await fbPatch(`students/${code}`, { section: secInfo.id }); } catch {}
        student.section = secInfo.id;
      }
    }

    res.json({
      success: true,
      data: {
        token,
        expiresAt: sess.expiresAt,
        student: {
          name: student.name,
          code,
          section: student.section || null,
          expiresAt: student.expiresAt,
          maxDevices,
          deviceId
        },
        yearId,
        subjectIds
      }
    });
  } catch (e) {
    console.error("[login]", e.message);
    jsonError(res, 500, e.message);
  }
});

app.post("/api/auth/logout", requireStudent, async (req, res) => {
  try {
    studentSessions.delete(req.sessionToken);
    await fbDelete(`sessions/${req.sessionToken}`);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.get("/api/auth/me", requireStudent, async (req, res) => {
  try {
    const s = req.student;
    let subjectIds = [];
    let yearId = CONFIG.DEFAULT_YEAR_ID;
    const secInfo = await resolveSection(s.section);
    if (secInfo) {
      subjectIds = secInfo.subjectIds || [];
      yearId = secInfo.yearId || yearId;
      if (secInfo.id) s.section = secInfo.id;
    }
    res.json({
      success: true,
      data: {
        name: s.name,
        code: req.session.code,
        section: s.section || null,
        expiresAt: s.expiresAt,
        maxDevices: s.maxDevices || 1,
        devices: Object.keys(s.devices || {}).length,
        deviceId: req.session.deviceId,
        yearId,
        subjectIds,
        sessionExpiresAt: req.session.expiresAt
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// CATALOG (student token required) — proxies upstream, hides COURSATK token
// ═══════════════════════════════════════════════════════════
app.get("/api/config", requireStudent, async (req, res) => {
  let yearId = CONFIG.DEFAULT_YEAR_ID;
  let subjectIds = [];
  const secInfo = await resolveSection(req.student.section);
  if (secInfo) {
    yearId = secInfo.yearId || yearId;
    subjectIds = secInfo.subjectIds || [];
  }
  res.json({
    success: true,
    yearId,
    subjectIds,
    cryptoReady: Boolean(decryptPlaybackKeyFn),
    decryptSegments: true
  });
});

app.get("/api/subjects/:id", requireStudent, async (req, res) => {
  try {
    // 1) Load section subject IDs (Firebase + hardcoded catalog)
    let wantedIds = [];
    let yearId = Number(req.params.id) || CONFIG.DEFAULT_YEAR_ID;
    const secInfo = await resolveSection(req.student.section);
    if (secInfo) {
      if (Array.isArray(secInfo.subjectIds) && secInfo.subjectIds.length) {
        wantedIds = secInfo.subjectIds.map(Number).filter((n) => !Number.isNaN(n));
      }
      if (secInfo.yearId) yearId = Number(secInfo.yearId) || yearId;
    }
    console.log("[subjects]", {
      student: req.student.code,
      section: req.student.section,
      wantedIds
    });

    // 2) Fetch year subjects once (upstream list)
    const yearData = await upstreamJson(`/user/subjects/${encodeURIComponent(yearId)}`);
    let yearList = Array.isArray(yearData.data) ? yearData.data : [];
    const byId = new Map(yearList.map((s) => [Number(s.id), s]));

    // 3) If no section filter → return full year list
    if (!wantedIds.length) {
      return res.json({ ...yearData, data: yearList });
    }

    // 4) Resolve subjects — year list first, missing IDs in parallel via /teachers
    const cacheKey = `subjects:year:${yearId}`;
    const yearCached = cacheGet(cacheKey);
    if (yearCached) {
      yearList = yearCached;
      for (const s of yearList) byId.set(Number(s.id), s);
    } else {
      cacheSet(cacheKey, yearList, 60_000);
    }

    async function resolveOne(sid) {
      if (byId.has(sid)) return byId.get(sid);
      const ck = `subj:meta:${sid}`;
      const hit = cacheGet(ck);
      if (hit) return hit;
      try {
        const t = await upstreamJson(`/user/subjects/${sid}/teachers`);
        const d = t?.data;
        const item = {
          id: Number(d?.id) || sid,
          name: d?.name || `مادة ${sid}`,
          image_url: d?.image_url || null,
          year_id: yearId,
          is_published: true
        };
        cacheSet(ck, item, 5 * 60_000);
        return item;
      } catch (err) {
        console.warn(`[subjects] resolve ${sid}:`, err.message);
        return { id: sid, name: `مادة ${sid}`, image_url: null, year_id: yearId, is_published: true };
      }
    }

    const results = await Promise.all(wantedIds.map((sid, idx) =>
      resolveOne(sid).then((s) => ({ ...s, order_index: idx + 1 }))
    ));

    res.json({
      success: true,
      message: "Success",
      data: results
    });
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/subjects/:id/teachers", requireStudent, async (req, res) => {
  try {
    res.json(
      await upstreamJson(`/user/subjects/${encodeURIComponent(req.params.id)}/teachers`)
    );
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/teachers/:id/chapters", requireStudent, async (req, res) => {
  try {
    res.json(
      await upstreamJson(`/user/teachers/${encodeURIComponent(req.params.id)}/chapters`)
    );
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/chapters/:id/lectures", requireStudent, async (req, res) => {
  try {
    res.json(
      await upstreamJson(`/user/chapters/${encodeURIComponent(req.params.id)}/lectures`)
    );
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

app.get("/api/lectures/:id/content", requireStudent, async (req, res) => {
  try {
    res.json(
      await upstreamJson(`/user/lectures/${encodeURIComponent(req.params.id)}/content`)
    );
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// STREAM (student token) — decrypted segments
// ═══════════════════════════════════════════════════════════
app.post("/api/play/:videoId", requireStudent, async (req, res) => {
  try {
    const data = await upstreamJson(
      `/video/${encodeURIComponent(req.params.videoId)}/stream-weave/play`,
      { method: "POST", headers: { Accept: "application/json" } }
    );
    if (!data?.success || !data?.data?.token || !data?.data?.stream_url || !data?.data?.video_id) {
      throw new Error("Playback response ناقص");
    }
    const id = crypto.randomUUID();
    streamSessions.set(id, {
      id,
      videoId: String(data.data.video_id),
      token: data.data.token,
      streamUrl: data.data.stream_url,
      createdAt: now(),
      plainKey: null,
      defaultIv: null,
      allowedHosts: new Set([new URL(data.data.stream_url).hostname]),
      ownerCode: req.session.code
    });
    res.json({
      success: true,
      data: {
        session: id,
        video_id: data.data.video_id,
        manifest_url: `/api/stream/manifest/${id}`
      }
    });
  } catch (e) {
    jsonError(res, 502, e.message);
  }
});

function getStreamSession(id) {
  const s = streamSessions.get(id);
  if (!s) return null;
  if (now() - s.createdAt > CONFIG.STREAM_SESSION_MS) {
    streamSessions.delete(id);
    return null;
  }
  return s;
}

app.get("/api/stream/manifest/:sessionId", requireStudent, async (req, res) => {
  const session = getStreamSession(req.params.sessionId);
  if (!session) return jsonError(res, 404, "جلسة التشغيل منتهية");
  if (session.ownerCode !== req.session.code) {
    return jsonError(res, 403, "جلسة تشغيل ليست لك");
  }

  try {
    const master = await streamFetch(session, session.streamUrl, {}, req.headers);
    if (!master.ok) throw new Error(`Stream master HTTP ${master.status}`);
    const masterText = await master.text();
    const lines = masterText.split(/\r?\n/);

    let variant = null;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().startsWith("#EXT-X-STREAM-INF")) {
        const next = lines[i + 1]?.trim();
        if (next && !next.startsWith("#")) {
          variant = new URL(next, session.streamUrl).href;
          break;
        }
      }
    }

    if (variant) {
      const variantRes = await streamFetch(session, variant, {}, req.headers);
      if (!variantRes.ok) throw new Error(`Variant HTTP ${variantRes.status}`);
      return rewritePlaylist(
        req.params.sessionId, session, await variantRes.text(), variant, res, req.headers
      );
    }
    return rewritePlaylist(
      req.params.sessionId, session, masterText, session.streamUrl, res, req.headers
    );
  } catch (e) {
    console.error("[manifest]", e.message);
    jsonError(res, 502, e.message);
  }
});

async function rewritePlaylist(sessionId, session, text, baseUrl, res, clientHeaders) {
  try { session.allowedHosts.add(new URL(baseUrl).hostname); } catch {}
  const lines = text.split(/\r?\n/);
  const out = [];
  let mediaSeq = 0;
  let currentIv = null;
  let keyFetched = false;

  for (const raw of lines) {
    const t = raw.trim();
    if (t.startsWith("#EXT-X-MEDIA-SEQUENCE:")) mediaSeq = Number(t.split(":")[1]) || 0;
  }

  let segIndex = 0;
  for (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith("#EXT-X-KEY:")) {
      const uri = line.match(/URI="([^"]+)"/)?.[1];
      const ivHex = line.match(/IV=(0x[0-9a-fA-F]+|[0-9a-fA-F]{32})/i)?.[1];
      if (ivHex) currentIv = parseIvHex(ivHex);
      if (uri && !keyFetched) {
        const keyUrl = new URL(uri, baseUrl).href;
        try { session.allowedHosts.add(new URL(keyUrl).hostname); } catch {}
        const keyRes = await streamFetch(session, keyUrl, {}, clientHeaders);
        if (!keyRes.ok) throw new Error(`Key HTTP ${keyRes.status}`);
        const wrapped = Buffer.from(await keyRes.arrayBuffer());
        session.plainKey = await unwrapKey(wrapped, session.videoId);
        session.defaultIv = currentIv;
        keyFetched = true;
        console.log(`[key] unwrapped for ${session.videoId}`);
      }
      continue; // strip KEY — segments are plain
    }
    if (line && !line.startsWith("#")) {
      const segmentUrl = new URL(line, baseUrl).href;
      try { session.allowedHosts.add(new URL(segmentUrl).hostname); } catch {}
      const seq = mediaSeq + segIndex;
      const iv = currentIv || ivFromMediaSequence(seq);
      const payload = Buffer.from(
        JSON.stringify({ u: segmentUrl, iv: iv.toString("hex"), s: seq }),
        "utf8"
      ).toString("base64url");
      out.push(`/api/stream/segment/${sessionId}/${payload}`);
      segIndex++;
      continue;
    }
    out.push(raw);
  }
  if (!session.plainKey) throw new Error("فشل تجهيز مفتاح التشفير");

  res.set({
    "Content-Type": "application/vnd.apple.mpegurl",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*"
  });
  res.send(out.join("\n"));
}

app.get("/api/stream/segment/:sessionId/:encoded", requireStudent, async (req, res) => {
  const session = getStreamSession(req.params.sessionId);
  if (!session) return jsonError(res, 404, "جلسة التشغيل منتهية");
  if (session.ownerCode !== req.session.code) return jsonError(res, 403, "جلسة ليست لك");
  if (!session.plainKey) return jsonError(res, 404, "مفتاح غير متاح");

  let meta;
  try {
    meta = JSON.parse(Buffer.from(req.params.encoded, "base64url").toString("utf8"));
  } catch {
    return jsonError(res, 400, "segment meta غير صالح");
  }
  const url = meta?.u;
  if (!url || !allowedStreamUrl(url, session)) return jsonError(res, 403, "رابط غير مسموح");

  const iv = parseIvHex(meta.iv) || session.defaultIv || ivFromMediaSequence(meta.s || 0);
  try {
    const upstream = await streamFetch(session, url, {
      Range: req.headers.range || undefined
    }, req.headers);
    if (!upstream.ok && upstream.status !== 206) {
      throw new Error(`Segment HTTP ${upstream.status}`);
    }
    const encrypted = Buffer.from(await upstream.arrayBuffer());
    if (encrypted.length > CONFIG.MAX_PROXY_BYTES) {
      return jsonError(res, 413, "المقطع كبير");
    }
    let plain;
    try {
      plain = decryptSegment(encrypted, session.plainKey, iv);
    } catch {
      plain = encrypted;
    }
    res.status(200);
    res.set({
      "Content-Type": "video/mp2t",
      "Content-Length": String(plain.length),
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*"
    });
    res.send(plain);
  } catch (e) {
    if (!res.headersSent) jsonError(res, 502, e.message);
    else res.end();
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN AUTH
// ═══════════════════════════════════════════════════════════
app.post("/api/admin/login", rateLimit({ max: 20, windowMs: 60_000, scope: "admin-login" }), async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const ip = clientIp(req);
    if (!username || !password) return jsonError(res, 400, "يوزر وباسورد مطلوبين");

    const lock = checkLoginLock("admin", ip, username);
    if (lock && lock.locked) {
      res.setHeader("Retry-After", String(lock.sec));
      return jsonError(res, 429, `محاولات خاطئة كثيرة — حاول بعد ${Math.ceil(lock.sec / 60)} دقيقة`);
    }

    let adminId = null;
    let admin = null;
    let perms = null;

    function failAuth() {
      const fail = recordLoginFail("admin", ip, username);
      if (fail.locked) {
        res.setHeader("Retry-After", String(fail.sec));
        return jsonError(res, 429, "محاولات خاطئة كثيرة — حاول بعد 15 دقيقة");
      }
      return jsonError(res, 401, `بيانات الدخول خطأ (متبقي ${fail.remaining} محاولات)`);
    }

    if (username === CONFIG.BOOTSTRAP_ADMIN.username) {
      const ok = scryptVerify(password, CONFIG.BOOTSTRAP_ADMIN.passwordHash) ||
        password === CONFIG.BOOTSTRAP_ADMIN.passwordPlain;
      if (!ok) return failAuth();
      adminId = "bootstrap";
      perms = CONFIG.BOOTSTRAP_ADMIN.permissions;
      admin = { username, permissions: perms, bootstrap: true };
    } else {
      // Find admin by username in Firebase
      const all = (await fbGet("admins")) || {};
      for (const [id, a] of Object.entries(all)) {
        if (a && a.username === username && a.active !== false) {
          if (!scryptVerify(password, a.passwordHash)) {
            return failAuth();
          }
          adminId = id;
          admin = a;
          perms = a.permissions || {};
          break;
        }
      }
      if (!adminId) return failAuth();
    }
    clearLoginFail("admin", ip, username);

    const token = randomToken(32);
    const sess = {
      token,
      adminId,
      username,
      createdAt: now(),
      expiresAt: now() + CONFIG.ADMIN_SESSION_MS,
      bootstrap: adminId === "bootstrap"
    };
    adminSessions.set(token, sess);
    // Firebase optional — bootstrap admin works even if Firebase not configured yet
    if (getFirebaseUrl()) {
      try {
        await fbSet(`admin_sessions/${token}`, sess);
      } catch (err) {
        console.warn("[admin login] session fb skip:", err.message);
      }
    }

    res.json({
      success: true,
      data: {
        token,
        expiresAt: sess.expiresAt,
        username,
        permissions: perms,
        needsSetup: !getFirebaseUrl()
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.post("/api/admin/logout", requireAdmin(null), async (req, res) => {
  adminSessions.delete(req.adminToken);
  try { await fbDelete(`admin_sessions/${req.adminToken}`); } catch {}
  res.json({ success: true });
});

app.get("/api/admin/me", requireAdmin(null), (req, res) => {
  res.json({
    success: true,
    data: {
      username: req.admin.username,
      permissions: req.admin.permissions || {},
      bootstrap: !!req.admin.bootstrap
    }
  });
});


// ═══════════════════════════════════════════════════════════
// ADMIN — App config (Coursatk token)
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/config", requireAdmin("sections_manage"), async (_req, res) => {
  try {
    const remote = await fbGet("config");
    const token = await getCoursatkToken();
    const masked = token
      ? token.slice(0, 12) + "…" + token.slice(-8)
      : null;
    res.json({
      success: true,
      data: {
        coursatkTokenSet: Boolean(token),
        coursatkTokenMasked: masked,
        defaultYearId: CONFIG.DEFAULT_YEAR_ID,
        codeTypes: Object.fromEntries(
          Object.entries(CONFIG.CODE_TYPES).map(([k, v]) => [k, { label: v.label, ms: v.ms }])
        ),
        firebase: remote || {}
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** PUT /api/admin/config/token  { token: "eyJ..." } */
app.put("/api/admin/config/token", requireAdmin("admins_manage"), async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    if (token.length < 20) return jsonError(res, 400, "توكن غير صالح");
    await fbSet("config/coursatkToken", token);
    cachedCoursatkToken = token;
    cachedTokenAt = Date.now();
    res.json({ success: true, message: "تم تحديث توكن كورساتك" });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN — Students
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/students", requireAdmin("students_view"), async (_req, res) => {
  try {
    const all = (await fbGet("students")) || {};
    const list = Object.entries(all).map(([code, s]) => ({
      code,
      name: s.name,
      section: s.section || null,
      type: s.type || null,
      days: s.days || null,
      durationMs: s.durationMs || null,
      activatedAt: s.activatedAt || null,
      expiresAt: s.expiresAt || null,
      maxDevices: s.maxDevices || 1,
      devices: Object.keys(s.devices || {}).length,
      active: s.active !== false,
      createdAt: s.createdAt || null,
      status: !s.activatedAt ? "لم يبدأ" : (s.expiresAt && Date.now() > s.expiresAt ? "منتهي" : "نشط")
    }));
    list.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ success: true, data: list });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.get("/api/admin/students/:code", requireAdmin("students_view"), async (req, res) => {
  try {
    const code = req.params.code;
    const s = await fbGet(`students/${code}`);
    if (!s) return jsonError(res, 404, "الطالب غير موجود");
    res.json({
      success: true,
      data: {
        code,
        ...s,
        deviceList: Object.entries(s.devices || {}).map(([id, d]) => ({
          deviceId: id,
          ...d
        }))
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/**
 * POST /api/admin/students
 * { name, section, type: trial|month|term|year, maxDevices?: number, code?: "1234567" }
 */

/** Bulk import students (from cleaned CSV/JSON) */
app.post("/api/admin/students/import", requireAdmin("students_create"), async (req, res) => {
  try {
    const list = Array.isArray(req.body?.students) ? req.body.students : [];
    if (!list.length) return jsonError(res, 400, "لا توجد بيانات للاستيراد");
    if (list.length > 5000) return jsonError(res, 400, "الحد الأقصى 5000 كود في المرة");

    let created = 0, updated = 0, failed = 0;
    const errors = [];
    const t = now();
    const DAY = 24 * 3600 * 1000;

    for (const row of list) {
      try {
        // Accept English or Arabic column names (لوحة التحكم)
        let code = String(row.code || row["الكود"] || "").replace(/\D/g, "");
        if (code.length < 7) {
          failed++;
          errors.push({ code: row.code || row["الكود"], error: "كود غير صالح" });
          continue;
        }
        if (code.length < 9) code = code.padStart(9, "0");

        const name = String(row.name || row["الاسم"] || "بدون اسم").trim().slice(0, 120);
        const sectionRaw = row.section || row["الشعبة"] || "";
        const section = normalizeSection(sectionRaw) || String(sectionRaw).trim() || null;
        let active = row.active !== false && row.active !== 0 && row.active !== "0";
        if (row["الحالة"] != null) {
          active = String(row["الحالة"]).trim() === "فعال";
        }
        const remainingText = String(row["المتبقي"] || row.remaining || "").trim();
        let pending = row.pendingActivation === true || row.pendingActivation === 1 || row.pendingActivation === "1";
        if (remainingText === "غير محددة" || remainingText === "غير محدد") pending = true;
        let days = row.days != null ? Number(row.days) : null;
        if (days == null && remainingText) {
          if (remainingText === "انتهى" || remainingText === "منتهي") days = 0;
          else {
            const m = remainingText.match(/(\d+)\s*يوم/);
            if (m) days = Number(m[1]);
          }
        }
        if (remainingText === "انتهى" || remainingText === "منتهي") {
          active = false;
          row.expired = true;
        }
        const durationMs =
          Number(row.durationMs) > 0
            ? Number(row.durationMs)
            : days != null && days >= 0
              ? Math.round(days * DAY)
              : resolveDurationMs({ type: row.type || "year", days });

        const existing = await fbGet(`students/${code}`);
        const record = {
          name,
          section,
          type: String(row.type || (pending ? "year" : "custom")),
          days: days,
          durationMs: durationMs || null,
          maxDevices: Math.max(1, Math.min(10, Number(row.maxDevices || existing?.maxDevices || 1))),
          devices: existing?.devices || {},
          bannedDevices: existing?.bannedDevices || {},
          active,
          createdAt: existing?.createdAt || t,
          createdBy: req.admin.username,
          importedAt: t
        };

        if (pending || (!existing && (days == null || row.expiresAt == null) && !row.expired)) {
          // timer starts on first login
          if (pending || row.expiresAt == null) {
            record.activatedAt = null;
            record.expiresAt = null;
            if (!record.durationMs) record.durationMs = 365 * DAY;
          }
        }

        if (row.expired === true || (days != null && days <= 0 && !pending)) {
          record.activatedAt = existing?.activatedAt || t - DAY;
          record.expiresAt = t - 1000;
          record.active = false;
        } else if (!pending && days != null && days > 0) {
          // remaining days from import moment
          record.activatedAt = existing?.activatedAt || t;
          record.expiresAt = t + Math.round(days * DAY);
          record.durationMs = record.durationMs || Math.round(days * DAY);
        } else if (!pending && Number(row.expiresAt) > 0) {
          record.expiresAt = Number(row.expiresAt);
          record.activatedAt = Number(row.activatedAt) || existing?.activatedAt || t;
        }

        await fbSet(`students/${code}`, { ...(existing || {}), ...record });
        if (existing) updated++;
        else created++;
      } catch (e) {
        failed++;
        errors.push({ code: row.code, error: e.message });
      }
    }

    res.json({
      success: true,
      data: { created, updated, failed, total: list.length, errors: errors.slice(0, 50) }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.post("/api/admin/students", requireAdmin("students_create"), async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const section = normalizeSection(req.body?.section) || String(req.body?.section || "").trim() || null;
    const type = String(req.body?.type || "custom");
    const maxDevices = Math.max(1, Math.min(10, Number(req.body?.maxDevices || 1)));
    let code = String(req.body?.code || "").trim();

    if (!name) return jsonError(res, 400, "اسم الطالب مطلوب");

    const duration = resolveDurationMs(req.body);
    if (!duration || duration <= 0) {
      return jsonError(res, 400, "حدد نوع الباقة أو عدد الأيام");
    }

    if (code) {
      if (!/^\d{9}$/.test(code)) return jsonError(res, 400, "الكود يجب 9 أرقام");
      const exists = await fbGet(`students/${code}`);
      if (exists) return jsonError(res, 409, "الكود مستخدم بالفعل");
    } else {
      for (let i = 0; i < 30; i++) {
        code = randomCode9();
        const exists = await fbGet(`students/${code}`);
        if (!exists) break;
      }
    }

    const record = {
      name,
      section: section || null,
      type: req.body?.days != null ? "custom" : type,
      days: req.body?.days != null ? Number(req.body.days) : null,
      durationMs: duration, // starts on first student login
      maxDevices,
      devices: {},
      bannedDevices: {},
      active: true,
      createdAt: now(),
      activatedAt: null, // set on first login
      expiresAt: null,   // set on first login = activatedAt + durationMs
      createdBy: req.admin.username
    };
    await fbSet(`students/${code}`, record);
    res.json({ success: true, data: { code, ...record } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.patch("/api/admin/students/:code", requireAdmin("students_edit"), async (req, res) => {
  try {
    const code = req.params.code;
    const s = await fbGet(`students/${code}`);
    if (!s) return jsonError(res, 404, "غير موجود");

    const patch = {};
    if (req.body.name != null) patch.name = String(req.body.name).trim();
    if (req.body.section != null) patch.section = normalizeSection(req.body.section) || String(req.body.section).trim() || null;
    if (req.body.maxDevices != null) {
      patch.maxDevices = Math.max(1, Math.min(10, Number(req.body.maxDevices)));
    }
    if (req.body.active != null) patch.active = Boolean(req.body.active);
    if (req.body.type && (CONFIG.CODE_TYPES[req.body.type] || (runtime.packages || []).some((p) => p.id === req.body.type))) {
      patch.type = req.body.type;
      const dur = resolveDurationMs({ type: req.body.type });
      patch.durationMs = dur;
      if (req.body.renew) {
        // restart from now
        patch.activatedAt = now();
        patch.expiresAt = now() + dur;
      } else if (req.body.resetTimer) {
        // wait for next student login
        patch.activatedAt = null;
        patch.expiresAt = null;
      }
    }
    // custom days
    if (req.body.days != null && Number(req.body.days) > 0) {
      patch.type = "custom";
      patch.days = Number(req.body.days);
      const dur = resolveDurationMs({ days: req.body.days });
      patch.durationMs = dur;
      if (req.body.renew) {
        patch.activatedAt = now();
        patch.expiresAt = now() + dur;
      } else if (req.body.resetTimer || req.body.renew === false) {
        patch.activatedAt = null;
        patch.expiresAt = null;
      }
    }
    // explicit reset: timer starts again on next login
    if (req.body.resetTimer === true) {
      patch.activatedAt = null;
      patch.expiresAt = null;
    }
    if (req.body.extendMs) {
      const base = Math.max(s.expiresAt || now(), now());
      patch.expiresAt = base + Number(req.body.extendMs);
    }
    if (req.body.extendDays != null) {
      const base = Math.max(s.expiresAt || now(), now());
      patch.expiresAt = base + Number(req.body.extendDays) * 24 * 3600 * 1000;
    }
    await fbPatch(`students/${code}`, patch);

    // force logout all sessions for this code
    if (req.body.forceLogout) {
      const sessions = (await fbGet("sessions")) || {};
      for (const [tok, sess] of Object.entries(sessions)) {
        if (sess && sess.code === code) {
          studentSessions.delete(tok);
          await fbDelete(`sessions/${tok}`);
        }
      }
    }

    res.json({ success: true, data: { code, ...s, ...patch } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/students/:code", requireAdmin("students_delete"), async (req, res) => {
  try {
    const code = req.params.code;
    // Kill all sessions for this code
    const sessions = (await fbGet("sessions")) || {};
    for (const [tok, sess] of Object.entries(sessions)) {
      if (sess && sess.code === code) {
        studentSessions.delete(tok);
        await fbDelete(`sessions/${tok}`);
      }
    }
    await fbDelete(`students/${code}`);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Force logout all devices/sessions for a code */
app.post("/api/admin/students/:code/logout-all", requireAdmin("devices_kick"), async (req, res) => {
  try {
    const code = req.params.code;
    const s = await fbGet(`students/${code}`);
    if (!s) return jsonError(res, 404, "غير موجود");
    const sessions = (await fbGet("sessions")) || {};
    let n = 0;
    for (const [tok, sess] of Object.entries(sessions)) {
      if (sess && sess.code === code) {
        studentSessions.delete(tok);
        await fbDelete(`sessions/${tok}`);
        n++;
      }
    }
    // clear devices list optional
    if (req.body?.clearDevices) {
      await fbPatch(`students/${code}`, { devices: {} });
    }
    res.json({ success: true, message: `تم تسجيل الخروج من ${n} جلسة`, killed: n });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Ban / unban a device on a student code */
app.post("/api/admin/students/:code/devices/:deviceId/ban", requireAdmin("devices_kick"), async (req, res) => {
  try {
    const code = req.params.code;
    const deviceId = String(req.params.deviceId);
    const s = await fbGet(`students/${code}`);
    if (!s) return jsonError(res, 404, "غير موجود");
    const banned = { ...(s.bannedDevices || {}) };
    banned[deviceId] = { bannedAt: now(), by: req.admin.username, reason: String(req.body?.reason || "") };
    const devices = { ...(s.devices || {}) };
    delete devices[deviceId];
    await fbPatch(`students/${code}`, { bannedDevices: banned, devices });
    // kill sessions for this device
    const sessions = (await fbGet("sessions")) || {};
    for (const [tok, sess] of Object.entries(sessions)) {
      if (sess && sess.code === code && sess.deviceId === deviceId) {
        studentSessions.delete(tok);
        await fbDelete(`sessions/${tok}`);
      }
    }
    res.json({ success: true, message: "تم حظر الجهاز" });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/students/:code/devices/:deviceId/ban", requireAdmin("devices_kick"), async (req, res) => {
  try {
    const code = req.params.code;
    const deviceId = String(req.params.deviceId);
    const s = await fbGet(`students/${code}`);
    if (!s) return jsonError(res, 404, "غير موجود");
    const banned = { ...(s.bannedDevices || {}) };
    delete banned[deviceId];
    await fbPatch(`students/${code}`, { bannedDevices: banned });
    res.json({ success: true, message: "تم رفع الحظر" });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN — Runtime settings (Firebase URL, token, packages, agents)
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/runtime", requireAdmin("admins_manage"), async (_req, res) => {
  res.json({
    success: true,
    data: {
      firebaseUrl: runtime.firebaseUrl || "",
      storageBucket: runtime.storageBucket || getStorageBucket(),
      firebaseConfigured: Boolean(getFirebaseUrl()),
      coursatkTokenSet: Boolean(getCoursatkTokenSync()),
      coursatkTokenMasked: getCoursatkTokenSync()
        ? getCoursatkTokenSync().slice(0, 12) + "…" + getCoursatkTokenSync().slice(-6)
        : "",
      siteName: runtime.siteName,
      packages: runtime.packages || [],
      agents: runtime.agents || []
    }
  });
});

app.put("/api/admin/runtime", requireAdmin("admins_manage"), async (req, res) => {
  try {
    const b = req.body || {};
    if (b.firebaseUrl != null) {
      const url = String(b.firebaseUrl).trim().replace(/\/$/, "");
      if (url && !url.startsWith("https://")) {
        return jsonError(res, 400, "رابط Firebase يجب أن يبدأ بـ https://");
      }
      runtime.firebaseUrl = url;
      CONFIG.FIREBASE = url;
    }
    if (b.coursatkToken != null && String(b.coursatkToken).trim()) {
      runtime.coursatkToken = String(b.coursatkToken).trim();
      CONFIG.COURSATK_TOKEN = runtime.coursatkToken;
      // also mirror to Firebase if available
      try {
        if (getFirebaseUrl()) await fbSet("config/coursatkToken", runtime.coursatkToken);
      } catch {}
    }
    if (b.siteName != null) runtime.siteName = String(b.siteName).trim() || "كورساتك";
    if (Array.isArray(b.packages)) {
      runtime.packages = b.packages.map((p) => ({
        id: String(p.id || "").trim() || ("pkg_" + Date.now()),
        name: String(p.name || "").trim() || "باقة",
        price: Number(p.price) || 0,
        days: Math.max(0, Number(p.days) || 0),
        hours: Math.max(0, Number(p.hours) || 0),
        active: p.active !== false
      }));
    }
    if (Array.isArray(b.agents)) {
      runtime.agents = b.agents.map((a) => ({
        id: String(a.id || ("ag_" + Math.random().toString(36).slice(2, 8))),
        name: String(a.name || "").trim(),
        telegram: String(a.telegram || "").trim().replace(/^@/, ""),
        active: a.active !== false
      })).filter((a) => a.name);
    }
    saveRuntimeFile();
    cacheDel("fb:site");
    cacheDel("subjects:");
    // mirror packages/agents to Firebase for redundancy
    try {
      if (getFirebaseUrl()) {
        await fbSet("site/packages", runtime.packages);
        await fbSet("site/agents", runtime.agents);
        await fbSet("site/name", runtime.siteName);
      }
    } catch (e) {
      console.warn("[runtime] fb mirror:", e.message);
    }
    res.json({ success: true, message: "تم حفظ الإعدادات", data: { firebaseConfigured: Boolean(getFirebaseUrl()) } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.put("/api/admin/packages", requireAdmin("sections_manage"), async (req, res) => {
  try {
    if (!Array.isArray(req.body?.packages)) return jsonError(res, 400, "packages array required");
    runtime.packages = req.body.packages.map((p) => ({
      id: String(p.id || "").trim() || ("pkg_" + Date.now()),
      name: String(p.name || "").trim() || "باقة",
      price: Number(p.price) || 0,
      days: Math.max(0, Number(p.days) || 0),
      hours: Math.max(0, Number(p.hours) || 0),
      active: p.active !== false
    }));
    saveRuntimeFile();
    try { if (getFirebaseUrl()) await fbSet("site/packages", runtime.packages); } catch {}
    res.json({ success: true, data: runtime.packages });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.put("/api/admin/agents", requireAdmin("sections_manage"), async (req, res) => {
  try {
    if (!Array.isArray(req.body?.agents)) return jsonError(res, 400, "agents array required");
    runtime.agents = req.body.agents.map((a) => ({
      id: String(a.id || ("ag_" + Math.random().toString(36).slice(2, 8))),
      name: String(a.name || "").trim(),
      telegram: String(a.telegram || "").trim().replace(/^@/, ""),
      active: a.active !== false
    })).filter((a) => a.name);
    saveRuntimeFile();
    try { if (getFirebaseUrl()) await fbSet("site/agents", runtime.agents); } catch {}
    res.json({ success: true, data: runtime.agents });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});


/** Kick device → force logout that device */
app.delete(
  "/api/admin/students/:code/devices/:deviceId",
  requireAdmin("devices_kick"),
  async (req, res) => {
    try {
      const { code, deviceId } = req.params;
      const s = await fbGet(`students/${code}`);
      if (!s) return jsonError(res, 404, "غير موجود");

      const devices = { ...(s.devices || {}) };
      delete devices[deviceId];
      await fbSet(`students/${code}/devices`, devices);

      // Invalidate sessions for this device
      const sessions = (await fbGet("sessions")) || {};
      for (const [tok, sess] of Object.entries(sessions)) {
        if (sess && sess.code === code && sess.deviceId === deviceId) {
          studentSessions.delete(tok);
          await fbDelete(`sessions/${tok}`);
        }
      }
      res.json({ success: true, message: "تم تسجيل خروج الجهاز" });
    } catch (e) {
      jsonError(res, 500, e.message);
    }
  }
);

// ═══════════════════════════════════════════════════════════
// ADMIN — Sections (شعب) + subject IDs
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/sections", requireAdmin("sections_manage"), async (_req, res) => {
  try {
    const all = (await fbGet("sections")) || {};
    const list = Object.entries(all).map(([id, s]) => ({ id, ...s }));
    res.json({ success: true, data: list });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/**
 * PUT /api/admin/sections/:id
 * { name, yearId?, subjectIds: number[] }
 */
app.put("/api/admin/sections/:id", requireAdmin("sections_manage"), async (req, res) => {
  try {
    const id = String(req.params.id).trim().replace(/[^\w\u0600-\u06FF\-]/g, "_");
    const name = String(req.body?.name || id).trim();
    const yearId = Number(req.body?.yearId || CONFIG.DEFAULT_YEAR_ID);
    const subjectIds = Array.isArray(req.body?.subjectIds)
      ? req.body.subjectIds.map(Number).filter((n) => !Number.isNaN(n))
      : [];
    const record = { name, yearId, subjectIds, updatedAt: now() };
    await fbSet(`sections/${id}`, record);
    res.json({ success: true, data: { id, ...record } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/sections/:id", requireAdmin("sections_manage"), async (req, res) => {
  try {
    await fbDelete(`sections/${req.params.id}`);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN — manage other admins
// ═══════════════════════════════════════════════════════════
app.get("/api/admin/admins", requireAdmin("admins_manage"), async (_req, res) => {
  try {
    const all = (await fbGet("admins")) || {};
    const list = Object.entries(all).map(([id, a]) => ({
      id,
      username: a.username,
      permissions: a.permissions || {},
      active: a.active !== false,
      createdAt: a.createdAt || null
    }));
    res.json({
      success: true,
      data: [
        {
          id: "bootstrap",
          username: CONFIG.BOOTSTRAP_ADMIN.username,
          permissions: CONFIG.BOOTSTRAP_ADMIN.permissions,
          active: true,
          bootstrap: true
        },
        ...list
      ]
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/**
 * POST /api/admin/admins
 * { username, password, permissions: { students_create, ... } }
 */
app.post("/api/admin/admins", requireAdmin("admins_manage"), async (req, res) => {
  try {
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    if (!username || username.length < 3) return jsonError(res, 400, "يوزر غير صالح");
    if (!password || password.length < 6) return jsonError(res, 400, "باسورد قصير");
    if (username === CONFIG.BOOTSTRAP_ADMIN.username) {
      return jsonError(res, 409, "اسم محجوز");
    }

    const all = (await fbGet("admins")) || {};
    for (const a of Object.values(all)) {
      if (a && a.username === username) return jsonError(res, 409, "اليوزر موجود");
    }

    const permissions = {
      students_view: !!req.body?.permissions?.students_view,
      students_create: !!req.body?.permissions?.students_create,
      students_edit: !!req.body?.permissions?.students_edit,
      students_delete: !!req.body?.permissions?.students_delete,
      devices_kick: !!req.body?.permissions?.devices_kick,
      sections_manage: !!req.body?.permissions?.sections_manage,
      admins_manage: !!req.body?.permissions?.admins_manage
    };

    const id = crypto.randomUUID();
    const record = {
      username,
      passwordHash: scryptHash(password),
      permissions,
      active: true,
      createdAt: now(),
      createdBy: req.admin.username
    };
    await fbSet(`admins/${id}`, record);
    res.json({
      success: true,
      data: { id, username, permissions, active: true }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.patch("/api/admin/admins/:id", requireAdmin("admins_manage"), async (req, res) => {
  try {
    if (req.params.id === "bootstrap") {
      return jsonError(res, 400, "لا يمكن تعديل الأدمن الأساسي من هنا");
    }
    const a = await fbGet(`admins/${req.params.id}`);
    if (!a) return jsonError(res, 404, "غير موجود");
    const patch = {};
    if (req.body.password) patch.passwordHash = scryptHash(String(req.body.password));
    if (req.body.permissions) {
      patch.permissions = {
        students_view: !!req.body.permissions.students_view,
        students_create: !!req.body.permissions.students_create,
        students_edit: !!req.body.permissions.students_edit,
        students_delete: !!req.body.permissions.students_delete,
        devices_kick: !!req.body.permissions.devices_kick,
        sections_manage: !!req.body.permissions.sections_manage,
        admins_manage: !!req.body.permissions.admins_manage
      };
    }
    if (req.body.active != null) patch.active = Boolean(req.body.active);
    await fbPatch(`admins/${req.params.id}`, patch);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/admins/:id", requireAdmin("admins_manage"), async (req, res) => {
  try {
    if (req.params.id === "bootstrap") {
      return jsonError(res, 400, "لا يمكن حذف الأدمن الأساسي");
    }
    await fbDelete(`admins/${req.params.id}`);
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});


// ═══════════════════════════════════════════════════════════

/** ── Guest contact (no login) ──
 * Client generates guestId (uuid) and stores in localStorage.
 * Threads live under messages/guest_{guestId}
 */
function guestThreadKey(guestId) {
  const id = String(guestId || "").replace(/[^a-zA-Z0-9_\-]/g, "").slice(0, 64);
  if (id.length < 8) return null;
  return "guest_" + id;
}

/** Public: send message to admin without login */
app.post("/api/public/contact", rateLimit({ max: 12, windowMs: 60_000, scope: "public-contact" }), async (req, res) => {
  try {
    const guestId = String(req.body?.guestId || "").trim();
    const key = guestThreadKey(guestId);
    if (!key) return jsonError(res, 400, "guestId مطلوب (8 أحرف على الأقل)");

    const name = String(req.body?.name || "زائر").trim().slice(0, 80) || "زائر";
    const phone = String(req.body?.phone || "").trim().slice(0, 30);
    const text = String(req.body?.text || "").trim().slice(0, 2000);

    const id = makeMsgId();
    let mediaMeta = null;
    if (req.body?.media) {
      try {
        mediaMeta = saveMediaFile(key, id, req.body.media);
      } catch (e) {
        return jsonError(res, 400, e.message);
      }
    }
    if (!text && !mediaMeta) return jsonError(res, 400, "اكتب رسالة أو أرسل صورة/تسجيل");

    const msg = {
      from: "guest",
      type: mediaMeta ? mediaMeta.kind : "text",
      text: text || (mediaMeta?.kind === "image" ? "📷 صورة" : mediaMeta?.kind === "audio" ? "🎤 رسالة صوتية" : ""),
      name,
      phone: phone || null,
      ownerCode: key,
      guest: true,
      createdAt: now(),
      read: false
    };
    if (mediaMeta) {
      msg.mediaUrl = mediaMeta.url;
      msg.mime = mediaMeta.mime;
      msg.size = mediaMeta.size;
      msg.fileName = mediaMeta.fileName;
      msg.storage = mediaMeta.storage || "local";
      if (mediaMeta.duration) msg.duration = mediaMeta.duration;
    }

    await fbSet(`messages/${key}/messages/${id}`, msg);
    const cur = (await fbGet(`messages/${key}`)) || {};
    await fbPatch(`messages/${key}`, {
      updatedAt: now(),
      studentName: name,
      section: "guest",
      ownerCode: key,
      guest: true,
      phone: phone || cur.phone || null,
      unreadAdmin: Number(cur.unreadAdmin || 0) + 1,
      unreadStudent: 0
    });

    res.json({
      success: true,
      data: { id, guestId, threadKey: key, ...msg }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Public: fetch my guest thread (replies from admin) */
app.get("/api/public/contact/:guestId", rateLimit({ max: 40, windowMs: 60_000, scope: "public-contact-get" }), async (req, res) => {
  try {
    const key = guestThreadKey(req.params.guestId);
    if (!key) return jsonError(res, 400, "guestId غير صالح");
    const thread = (await fbGet(`messages/${key}`)) || { messages: {} };
    const list = Object.entries(thread.messages || {})
      .map(([id, m]) => ({ id, ...m }))
      .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    // mark guest read
    try { await fbPatch(`messages/${key}`, { unreadStudent: 0 }); } catch {}
    res.json({
      success: true,
      data: {
        guestId: String(req.params.guestId),
        threadKey: key,
        name: thread.studentName || "زائر",
        messages: list,
        unread: Number(thread.unreadStudent || 0)
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});


// Messaging — student <-> admin (stored in Firebase)
// ═══════════════════════════════════════════════════════════

function makeMsgId() {
  return "m_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
}

function studentCode(req) {
  const c = String(req.student?.code || req.session?.code || "").trim();
  if (!/^\d{7,12}$/.test(c)) return null;
  return c;
}

const MEDIA_MAX_BYTES = 12 * 1024 * 1024; // 12MB
const MEDIA_ALLOWED = {
  image: new Set(["image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif"]),
  audio: new Set(["audio/webm", "audio/ogg", "audio/mpeg", "audio/mp4", "audio/wav", "audio/x-wav", "audio/aac", "audio/mp3"])
};

function detectMediaKind(mime) {
  const m = String(mime || "").toLowerCase().split(";")[0].trim();
  if (MEDIA_ALLOWED.image.has(m) || m.startsWith("image/")) return "image";
  if (MEDIA_ALLOWED.audio.has(m) || m.startsWith("audio/")) return "audio";
  return null;
}

function extFromMime(mime) {
  const m = String(mime || "").toLowerCase().split(";")[0].trim();
  const map = {
    "image/jpeg": "jpg", "image/jpg": "jpg", "image/png": "png",
    "image/webp": "webp", "image/gif": "gif",
    "audio/webm": "webm", "audio/ogg": "ogg", "audio/mpeg": "mp3",
    "audio/mp3": "mp3", "audio/mp4": "m4a", "audio/wav": "wav",
    "audio/x-wav": "wav", "audio/aac": "aac"
  };
  return map[m] || "bin";
}

/** Save media on Railway disk: data/media/{code}/{file} */
function saveMediaFile(code, msgId, media) {
  if (!media) return null;
  let mime = String(media.mime || media.type || "").toLowerCase();
  let b64 = media.data || media.base64 || "";
  if (typeof b64 !== "string" || !b64) return null;

  const dataUrl = b64.match(/^data:([^;]+);base64,(.+)$/i);
  if (dataUrl) {
    mime = dataUrl[1].toLowerCase();
    b64 = dataUrl[2];
  }
  b64 = b64.replace(/\s/g, "");
  const kind = detectMediaKind(mime);
  if (!kind) throw new Error("نوع الملف غير مدعوم (صور: jpg/png/webp — صوت: webm/ogg/mp3/wav)");

  let buf;
  try {
    buf = Buffer.from(b64, "base64");
  } catch {
    throw new Error("بيانات الملف غير صالحة");
  }
  if (!buf.length) throw new Error("الملف فاضي");
  if (buf.length > MEDIA_MAX_BYTES) throw new Error("حجم الملف كبير (الحد 12 ميجا)");

  const mimeClean = mime.split(";")[0].trim();
  const dir = path.join(typeof MEDIA_DIR !== 'undefined' ? MEDIA_DIR : path.join(__dirname, 'data', 'media'), String(code));
  fs.mkdirSync(dir, { recursive: true });
  const fileName = `${msgId}.${extFromMime(mimeClean)}`;
  const full = path.join(dir, fileName);
  fs.writeFileSync(full, buf);

  return {
    kind,
    mime: mimeClean,
    size: buf.length,
    fileName,
    url: `/api/media/${encodeURIComponent(code)}/${encodeURIComponent(fileName)}`,
    storage: "local",
    duration: media.duration != null ? Number(media.duration) : null
  };
}

function deleteMediaFile(code, fileName) {
  if (!code || !fileName) return;
  const safe = path.basename(String(fileName));
  const full = path.join(MEDIA_DIR, String(code), safe);
  try { if (fs.existsSync(full)) fs.unlinkSync(full); } catch {}
}





/** Student: list ONLY my messages */
app.get("/api/messages", requireStudent, async (req, res) => {
  try {
    const code = studentCode(req);
    if (!code) return jsonError(res, 401, "كود الجلسة غير صالح");
    const thread = (await fbGet(`messages/${code}`)) || { messages: {}, updatedAt: 0 };
    // ignore any thread that was mis-keyed
    const list = Object.entries(thread.messages || {})
      .map(([id, m]) => ({ id, ...m }))
      .filter((m) => !m.ownerCode || m.ownerCode === code)
      .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    res.json({
      success: true,
      data: {
        code,
        messages: list,
        unreadStudent: Number(thread.unreadStudent || 0),
        unreadAdmin: Number(thread.unreadAdmin || 0)
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Student: send text / image / voice note
 * body: { text?, media?: { mime, data: base64|dataURL, duration? } }
 */
app.post("/api/messages", requireStudent, rateLimit({ max: 60, windowMs: 60_000, scope: "msg-student" }), async (req, res) => {
  try {
    const text = String(req.body?.text || "").trim().slice(0, 2000);
    const code = studentCode(req);
    if (!code) return jsonError(res, 401, "كود الجلسة غير صالح");
    const id = makeMsgId();

    let mediaMeta = null;
    if (req.body?.media) {
      try {
        mediaMeta = saveMediaFile(code, id, req.body.media);
      } catch (e) {
        return jsonError(res, 400, e.message);
      }
    }
    if (!text && !mediaMeta) return jsonError(res, 400, "اكتب رسالة أو أرسل صورة/تسجيل");

    const msg = {
      from: "student",
      type: mediaMeta ? mediaMeta.kind : "text",
      text: text || (mediaMeta?.kind === "image" ? "📷 صورة" : mediaMeta?.kind === "audio" ? "🎤 رسالة صوتية" : ""),
      name: req.student.name || code,
      ownerCode: code,
      createdAt: now(),
      read: false
    };
    if (mediaMeta) {
      msg.mediaUrl = mediaMeta.url;
      msg.mime = mediaMeta.mime;
      msg.size = mediaMeta.size;
      msg.fileName = mediaMeta.fileName;
      msg.storage = mediaMeta.storage || "firebase";
      if (mediaMeta.objectPath) msg.objectPath = mediaMeta.objectPath;
      if (mediaMeta.duration) msg.duration = mediaMeta.duration;
    }

    await fbSet(`messages/${code}/messages/${id}`, msg);
    const cur = (await fbGet(`messages/${code}`)) || {};
    await fbPatch(`messages/${code}`, {
      updatedAt: now(),
      studentName: req.student.name || code,
      section: req.student.section || null,
      ownerCode: code,
      unreadAdmin: Number(cur.unreadAdmin || 0) + 1,
      unreadStudent: 0
    });
    res.json({ success: true, data: { id, ...msg } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Student: mark thread as read */
app.post("/api/messages/read", requireStudent, async (req, res) => {
  try {
    const code = studentCode(req);
    if (!code) return jsonError(res, 401, "كود الجلسة غير صالح");
    await fbPatch(`messages/${code}`, { unreadStudent: 0 });
    res.json({ success: true });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Student: delete one of my messages */
app.delete("/api/messages/:msgId", requireStudent, async (req, res) => {
  try {
    const code = studentCode(req);
    if (!code) return jsonError(res, 401, "كود الجلسة غير صالح");
    const msgId = String(req.params.msgId);
    const msg = await fbGet(`messages/${code}/messages/${msgId}`);
    if (!msg) return jsonError(res, 404, "الرسالة غير موجودة");
    if (msg.fileName) deleteMediaFile(code, msg.fileName);
    await fbDelete(`messages/${code}/messages/${msgId}`);
    res.json({ success: true, message: "تم حذف الرسالة" });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Student: clear entire my thread */
app.delete("/api/messages", requireStudent, async (req, res) => {
  try {
    const code = studentCode(req);
    if (!code) return jsonError(res, 401, "كود الجلسة غير صالح");
    await fbDelete(`messages/${code}`);
    res.json({ success: true, message: "تم مسح المحادثة" });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Admin: list all conversation threads */
app.get("/api/admin/messages", requireAdmin("students_view"), async (_req, res) => {
  try {
    const all = (await fbGet("messages")) || {};
    const threads = Object.entries(all)
      .filter(([code]) => {
        if (!code || code === "undefined") return false;
        if (/^\d{7,12}$/.test(String(code))) return true;
        if (String(code).startsWith("guest_")) return true;
        return false;
      })
      .map(([code, t]) => {
      const msgs = Object.values(t.messages || {});
      const last = msgs.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))[0];
      return {
        code,
        studentName: t.studentName || code,
        section: t.section || null,
        updatedAt: t.updatedAt || last?.createdAt || 0,
        unreadAdmin: Number(t.unreadAdmin || 0),
        lastMessage: last ? { text: last.text, type: last.type || 'text', from: last.from, createdAt: last.createdAt, mediaUrl: last.mediaUrl || null } : null,
        count: msgs.length
      };
    }).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    res.json({ success: true, data: threads });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Admin: get one thread */
app.get("/api/admin/messages/:code", requireAdmin("students_view"), async (req, res) => {
  try {
    const code = String(req.params.code);
    const thread = (await fbGet(`messages/${code}`)) || { messages: {} };
    const list = Object.entries(thread.messages || {})
      .map(([id, m]) => ({ id, ...m }))
      .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
    // mark admin read
    await fbPatch(`messages/${code}`, { unreadAdmin: 0 });
    res.json({
      success: true,
      data: {
        code,
        studentName: thread.studentName || code,
        messages: list
      }
    });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Admin: reply (text / image / voice)
 * body: { text?, media?: { mime, data, duration? } }
 */
app.post("/api/admin/messages/:code", requireAdmin("students_view"), rateLimit({ max: 120, windowMs: 60_000, scope: "msg-admin" }), async (req, res) => {
  try {
    const code = String(req.params.code).replace(/\D/g, "");
    if (!code) return jsonError(res, 400, "كود غير صالح");
    const text = String(req.body?.text || "").trim().slice(0, 2000);
    const id = makeMsgId();
    let mediaMeta = null;
    if (req.body?.media) {
      try {
        mediaMeta = saveMediaFile(code, id, req.body.media);
      } catch (e) {
        return jsonError(res, 400, e.message);
      }
    }
    if (!text && !mediaMeta) return jsonError(res, 400, "اكتب رد أو أرسل صورة/تسجيل");
    const msg = {
      from: "admin",
      type: mediaMeta ? mediaMeta.kind : "text",
      text: text || (mediaMeta?.kind === "image" ? "📷 صورة" : mediaMeta?.kind === "audio" ? "🎤 رسالة صوتية" : ""),
      name: req.admin.username || "أدمن",
      ownerCode: code,
      createdAt: now(),
      read: false
    };
    if (mediaMeta) {
      msg.mediaUrl = mediaMeta.url;
      msg.mime = mediaMeta.mime;
      msg.size = mediaMeta.size;
      msg.fileName = mediaMeta.fileName;
      msg.storage = mediaMeta.storage || "firebase";
      if (mediaMeta.objectPath) msg.objectPath = mediaMeta.objectPath;
      if (mediaMeta.duration) msg.duration = mediaMeta.duration;
    }
    await fbSet(`messages/${code}/messages/${id}`, msg);
    const cur = (await fbGet(`messages/${code}`)) || {};
    await fbPatch(`messages/${code}`, {
      updatedAt: now(),
      unreadStudent: Number(cur.unreadStudent || 0) + 1,
      unreadAdmin: 0,
      studentName: cur.studentName || code
    });
    res.json({ success: true, data: { id, ...msg } });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});



/** Admin: delete one message in a thread */
app.delete("/api/admin/messages/:code/:msgId", requireAdmin("students_view"), async (req, res) => {
  try {
    const code = String(req.params.code).trim();
    const msgId = String(req.params.msgId);
    const msg = await fbGet(`messages/${code}/messages/${msgId}`);
    if (msg?.fileName) deleteMediaFile(code, msg.fileName);
    await fbDelete(`messages/${code}/messages/${msgId}`);
    res.json({ success: true, message: "تم حذف الرسالة" });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

/** Admin: delete whole thread */
app.delete("/api/admin/messages/:code", requireAdmin("students_view"), async (req, res) => {
  try {
    const code = String(req.params.code).trim();
    await fbDelete(`messages/${code}`);
    res.json({ success: true, message: "تم حذف المحادثة" });
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});


/** Serve chat media (image/audio) — student owns thread OR admin */
app.get("/api/media/:code/:file", async (req, res) => {
  try {
    let code = String(req.params.code || "");
    // numeric student code OR guest_xxx thread folder
    if (code.startsWith("guest_")) {
      code = code.replace(/[^a-zA-Z0-9_\-]/g, "");
    } else {
      code = code.replace(/\D/g, "");
    }
    const file = path.basename(String(req.params.file || ""));
    if (!code || !file || file.includes("..")) return jsonError(res, 400, "طلب غير صالح");

    const token = getBearer(req) || String(req.query.token || "").trim();
    const isGuestPath = code.startsWith("guest_");

    // Guest media: allow if query guestId matches folder (public contact thread)
    let allowed = false;
    if (isGuestPath) {
      const gid = String(req.query.guestId || "").replace(/[^a-zA-Z0-9_\-]/g, "");
      if (gid && ("guest_" + gid) === code) allowed = true;
    }
    if (token) {
      const stu = studentSessions.get(token);
      if (stu && String(stu.code) === code) allowed = true;
      if (!allowed && adminSessions.get(token)) allowed = true;
      if (!allowed) {
        try {
          const remote = await fbGet(`sessions/${token}`);
          if (remote && String(remote.code) === code) allowed = true;
        } catch {}
      }
    }
    if (!allowed) return jsonError(res, 403, "غير مصرح");

    const full = path.join(MEDIA_DIR, code, file);
    if (!fs.existsSync(full)) return jsonError(res, 404, "الملف غير موجود");

    const ext = path.extname(file).toLowerCase();
    const mimeMap = {
      ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
      ".webp": "image/webp", ".gif": "image/gif",
      ".webm": "audio/webm", ".ogg": "audio/ogg", ".mp3": "audio/mpeg",
      ".m4a": "audio/mp4", ".wav": "audio/wav", ".aac": "audio/aac"
    };
    res.setHeader("Content-Type", mimeMap[ext] || "application/octet-stream");
    res.setHeader("Cache-Control", "private, max-age=86400");
    res.setHeader("Content-Disposition", `inline; filename="${file}"`);
    fs.createReadStream(full).pipe(res);
  } catch (e) {
    jsonError(res, 500, e.message);
  }
});

// ═══════════════════════════════════════════════════════════
// Fallback
// ═══════════════════════════════════════════════════════════
// Root / unknown — require client handshake (no API dump)
app.get("/", (_req, res) => {
  res.status(403).json({
    success: false,
    message: "خطأ: يلزم مصادقة. الوصول المباشر غير مسموح."
  });
});

app.use((req, res) => {
  res.status(403).json({
    success: false,
    message: "خطأ: يلزم مصادقة أو المسار غير موجود.",
    path: req.path
  });
});

// Cleanup timers
setInterval(() => {
  const t = now();
  for (const [k, s] of studentSessions) {
    if (s.expiresAt && t > s.expiresAt) studentSessions.delete(k);
  }
  for (const [k, s] of adminSessions) {
    if (s.expiresAt && t > s.expiresAt) adminSessions.delete(k);
  }
  for (const [k, s] of streamSessions) {
    if (t - s.createdAt > CONFIG.STREAM_SESSION_MS) streamSessions.delete(k);
  }
}, 60_000).unref();

// Boot: hash bootstrap password properly + load crypto
CONFIG.BOOTSTRAP_ADMIN.passwordHash = scryptHash(CONFIG.BOOTSTRAP_ADMIN.passwordPlain);
await loadDecryptionUtils();

// Load site packages/agents from Firebase if configured
try {
  if (getFirebaseUrl()) {
    const pkgs = await fbGet("site/packages");
    if (Array.isArray(pkgs) && pkgs.length) runtime.packages = pkgs;
    const ags = await fbGet("site/agents");
    if (Array.isArray(ags)) runtime.agents = ags;
    const sn = await fbGet("site/name");
    if (typeof sn === "string" && sn) runtime.siteName = sn;
    const tok = await fbGet("config/coursatkToken");
    if (typeof tok === "string" && tok.length > 20 && !runtime.coursatkToken) {
      runtime.coursatkToken = tok;
      CONFIG.COURSATK_TOKEN = tok;
    }
  }
} catch (e) {
  console.warn("[API] site load skip:", e.message);
}

if (!getFirebaseUrl()) {
  console.warn("[API] WARNING: Firebase URL not set — configure from admin panel (إعدادات التشغيل)");
}

// Seed default sections if missing
try {
  if (!getFirebaseUrl()) throw new Error("no firebase");
  // Always ensure correct subject IDs for the 3 main sections
  // علمي علوم: 57 عربي، 58 English، 59 فيزياء، 60 كيمياء، 61 أحياء
  // علمي رياضة: نفس علوم مع 65 رياضة بدل 61 أحياء
  // أدبي: 57 عربي، 58 English + 62،63،64
  const sectionDefaults = {};
  for (const [id, def] of Object.entries(SECTION_CATALOG)) {
    sectionDefaults[id] = { ...def, updatedAt: Date.now() };
  }
  // Sync sections only when missing or IDs changed (avoid write storm on every restart)
  const existing = (await fbGet("sections")) || {};
  let changed = 0;
  for (const [id, def] of Object.entries(sectionDefaults)) {
    const cur = existing[id];
    const same =
      cur &&
      Array.isArray(cur.subjectIds) &&
      cur.subjectIds.length === def.subjectIds.length &&
      def.subjectIds.every((x, i) => Number(cur.subjectIds[i]) === x);
    if (!same) {
      await fbSet(`sections/${id}`, { ...(cur || {}), ...def });
      changed++;
    }
  }
  console.log("[API] sections synced, updated:", changed);
} catch (e) {
  console.warn("[API] section seed skip:", e.message);
}

app.listen(CONFIG.PORT, () => {
  console.log(`[API] :${CONFIG.PORT} protected · segment-decrypt ON`);
  console.log(`[API] bootstrap admin ready (Hema)`);
});
