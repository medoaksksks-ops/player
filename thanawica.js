/**
 * Thanawica adapter — chemistry + math catalog & stream decrypt
 * Keeps Coursatk paths intact; only used when subject is chem/math.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BASE = "https://thanawica.com";
const UA =
  "Mozilla/5.0 (Linux; Android 15; Mobile) AppleWebKit/537.36 Chrome/153.0.0.0 Mobile Safari/537.36";

const LOGIN_ACTION = "40c2de9a49b9eba30762cac2299b44fa8c06d885db";

/** ملف بسيط جنب السيرفر: thanawica_code.txt — سطر واحد فيه الكود */
function loadCodeFromFile() {
  const candidates = [
    path.join(__dirname, "thanawica_code.txt"),
    path.join(process.cwd(), "thanawica_code.txt"),
    path.join(__dirname, "data", "thanawica_code.txt")
  ];
  for (const f of candidates) {
    try {
      if (!fs.existsSync(f)) continue;
      const raw = fs.readFileSync(f, "utf8").trim();
      // أول سطر أرقام فقط (تجاهل التعليقات)
      for (const line of raw.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith("#") || t.startsWith("//")) continue;
        const digits = t.replace(/\D/g, "");
        if (digits.length >= 7) return digits;
      }
    } catch {}
  }
  return "";
}

/** كوكي جاهزة: env THANAWICA_COOKIES أو ملف thanawica_cookies.txt */
function loadCookiesFromFile() {
  const candidates = [
    path.join(__dirname, "thanawica_cookies.txt"),
    path.join(process.cwd(), "thanawica_cookies.txt"),
    path.join(__dirname, "data", "thanawica_cookies.txt")
  ];
  for (const f of candidates) {
    try {
      if (!fs.existsSync(f)) continue;
      const raw = fs.readFileSync(f, "utf8").trim();
      for (const line of raw.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith("#") || t.startsWith("//")) continue;
        if (t.includes("student_session=")) return t;
      }
    } catch {}
  }
  return "";
}

function resolveThanawicaCookies() {
  const fromEnv = String(process.env.THANAWICA_COOKIES || "").trim();
  if (fromEnv.includes("student_session=")) return fromEnv;
  return loadCookiesFromFile();
}

function resolveThanawicaCode(explicit) {
  const fromArg = String(explicit || "").replace(/\D/g, "");
  if (fromArg.length >= 7) return fromArg;
  const fromEnv = String(process.env.THANAWICA_CODE || "").replace(/\D/g, "");
  if (fromEnv.length >= 7) return fromEnv;
  // من الكوكي لو موجودة
  const ck = resolveThanawicaCookies();
  const m = ck.match(/student_code=(\d+)/);
  if (m) return m[1];
  return loadCodeFromFile();
}


/** Year on Thanawica → subject ids for chem + math (scientific tracks) */
const YEAR_SUBJECTS = {
  27: { arabic: 150, english: 152, chemistry: 154, physics: 156, math: 160 },
  26: { arabic: 101, english: 104, chemistry: 111, physics: 114, math: 121, french: 128, german: 130, abilities: 174 }
};
const NAME_CHEM = /كيمياء|chemistry/i;
const NAME_MATH = /رياض|math|جبر|تفاضل|إحصاء|استاتيكا|ديناميكا/i;
const NAME_PHYS = /فيزياء|physics/i;
const NAME_AR = /عربي|عربية|arabic/i;
const NAME_EN = /english|إنجل|انجليز/i;
const NAME_BIO = /أحياء|احياء|biology/i;
const NAME_FR = /فرنس|french/i;
const NAME_DE = /ألمان|المان|german/i;

let session = {
  cookies: "",
  code: "",
  exp: 0
};

// ─── HTTP helpers ───────────────────────────────────────────
function parseSetCookies(res) {
  const raw = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
  const list = raw.length ? raw : [];
  // fallback: single set-cookie
  if (!list.length) {
    const one = res.headers.get("set-cookie");
    if (one) list.push(one);
  }
  const map = new Map();
  // merge with existing
  for (const part of (session.cookies || "").split(";").map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf("=");
    if (i > 0) map.set(part.slice(0, i), part.slice(i + 1));
  }
  for (const line of list) {
    const pair = String(line).split(";")[0];
    const i = pair.indexOf("=");
    if (i > 0) map.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

async function thFetch(urlPath, { method = "GET", body, headers = {}, action } = {}) {
  const url = urlPath.startsWith("http") ? urlPath : BASE + urlPath;
  const h = {
    "User-Agent": UA,
    "Accept-Language": "ar-EG,ar;q=0.9,en;q=0.8",
    ...(session.cookies ? { Cookie: session.cookies } : {}),
    ...headers
  };
  if (action) {
    h["next-action"] = action;
    h["Content-Type"] = "text/plain;charset=UTF-8";
    h["Accept"] = "text/x-component";
    h["Origin"] = BASE;
  }
  const res = await fetch(url, {
    method,
    headers: h,
    body,
    redirect: "manual",
    signal: AbortSignal.timeout(25_000)
  });
  const sc = parseSetCookies(res);
  if (sc) session.cookies = sc;
  return res;
}

/** Extract Set-Cookie (Node 18+ getSetCookie; fallback single header) */
function collectSetCookies(res) {
  try {
    if (typeof res.headers.getSetCookie === "function") {
      const list = res.headers.getSetCookie();
      if (Array.isArray(list) && list.length) return list.map(String);
    }
  } catch (_) {}
  try {
    const one = res.headers.get("set-cookie");
    if (one) return [String(one)];
  } catch (_) {}
  return [];
}

function mergeCookiesFromSetCookie(setCookieLines, existing = "") {
  const map = new Map();
  for (const part of (existing || "").split(";").map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf("=");
    if (i > 0) map.set(part.slice(0, i), part.slice(i + 1));
  }
  for (const line of setCookieLines || []) {
    const pair = String(line).split(";")[0];
    const i = pair.indexOf("=");
    if (i > 0) map.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
  return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}

export async function thanawicaLogin(code) {
  const codeStr = resolveThanawicaCode(code);
  // كوكي جاهزة (env أو thanawica_cookies.txt) — بدون login وبدون حد الأجهزة
  const readyCookies = resolveThanawicaCookies();
  if (readyCookies.includes("student_session=")) {
    session.cookies = readyCookies;
    session.code = codeStr || session.code || "cookie";
    session.exp = Date.now() + 12 * 3600_000;
    if (!session._loggedCookie) {
      session._loggedCookie = true;
      console.log("[thanawica] using ready cookies (no login)");
    }
    return session;
  }
  if (codeStr.length < 7) {
    throw new Error("حط كود ثناويكا في thanawica_code.txt أو كوكي في thanawica_cookies.txt");
  }
  if (session.code === codeStr && session.cookies.includes("student_session=") && Date.now() < session.exp) {
    return session;
  }

  // Pure Node fetch — no curl (Railway/minimal images often lack curl → ENOENT)
  const loginHeaders = {
    "User-Agent": UA,
    "Content-Type": "text/plain;charset=UTF-8",
    Accept: "text/x-component",
    Origin: BASE,
    Referer: `${BASE}/login`,
    "next-action": LOGIN_ACTION
  };

  let res;
  try {
    res = await fetch(`${BASE}/login`, {
      method: "POST",
      headers: loginHeaders,
      body: JSON.stringify([codeStr]),
      redirect: "manual",
      signal: AbortSignal.timeout(25_000)
    });
  } catch (e) {
    throw new Error("فشل الاتصال بثناويكا: " + (e.message || e));
  }

  session.cookies = mergeCookiesFromSetCookie(collectSetCookies(res), session.cookies);

  let bodyText = "";
  try {
    bodyText = await res.text();
  } catch {}

  // Retry once with any bootstrap cookies (some Next deployments need a prior cookie)
  if (!session.cookies.includes("student_session=")) {
    try {
      const res2 = await fetch(`${BASE}/login`, {
        method: "POST",
        headers: {
          ...loginHeaders,
          ...(session.cookies ? { Cookie: session.cookies } : {})
        },
        body: JSON.stringify([codeStr]),
        redirect: "manual",
        signal: AbortSignal.timeout(25_000)
      });
      session.cookies = mergeCookiesFromSetCookie(collectSetCookies(res2), session.cookies);
      try {
        bodyText = await res2.text();
      } catch {}
    } catch {}
  }

  if (!session.cookies.includes("student_session=")) {
    let msg = "فشل تسجيل الدخول على ثناويكا";
    const m = bodyText && bodyText.match(/"message":"([^"]+)"/);
    if (m) msg = m[1];
    else if (bodyText && /invalid|wrong|غير|خاطئ|منتهي/i.test(bodyText)) {
      msg = "كود ثناويكا غير صالح أو منتهي";
    }
    throw new Error(msg);
  }

  session.code = codeStr;
  session.exp = Date.now() + 6 * 3600_000;
  console.log("[thanawica] logged in as", codeStr);
  return session;
}

async function ensureLogin(code) {
  return thanawicaLogin(code || session.code || resolveThanawicaCode());
}

function extractFlight(html) {
  const parts = [];
  const re = /self\.__next_f\.push\(\[1,(.*?)\]\)/gs;
  let m;
  while ((m = re.exec(html))) {
    let s = m[1].trim();
    if (s.startsWith('"')) {
      try {
        s = JSON.parse(s);
      } catch {
        // partial / truncated chunk — keep raw without outer quotes if possible
        if (s.length > 2 && s.startsWith('"') && s.endsWith('"')) {
          try {
            s = s.slice(1, -1).replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
          } catch {
            continue;
          }
        } else continue;
      }
    }
    if (typeof s === "string" && s.length) parts.push(s);
  }
  // كمان فك الـ escaped JSON جوّه السكربت لو الـ push فشل جزئيًا
  if (!parts.length) {
    const esc = html.replace(/\\"/g, '"').replace(/\\\//g, "/");
    return esc;
  }
  return parts.join("\n");
}

/** id صالح لـ teachers/chapters/lectures (مش UUID media) */
function isSaneId(id) {
  const n = Number(id);
  return Number.isFinite(n) && n >= 10 && n < 1_000_000;
}

/** خريطة اسم → صورة من alt + src media */
function parseImageByName(flight) {
  const map = new Map();
  const re1 =
    /alt":"([^"]{2,120})"[\s\S]{0,500}?src":"(https:\/\/thanawica\.com\/api\/media\/[^"]+)"/g;
  const re2 =
    /src":"(https:\/\/thanawica\.com\/api\/media\/[^"]+)"[\s\S]{0,500}?alt":"([^"]{2,120})"/g;
  for (const m of flight.matchAll(re1)) {
    map.set(m[1].trim(), m[2]);
  }
  for (const m of flight.matchAll(re2)) {
    const name = m[2].trim();
    if (!map.has(name)) map.set(name, m[1]);
  }
  return map;
}

/** "ساعة و35 دقيقة" / "45 دقيقة" / "ساعتين" → ثواني */
function parseArabicDuration(str) {
  const s = String(str || "");
  let sec = 0;
  if (/ساعتين/.test(s)) sec += 2 * 3600;
  else if (/ساعات/.test(s)) {
    const h = s.match(/(\d+)\s*ساعات/);
    sec += h ? Number(h[1]) * 3600 : 0;
  } else if (/ساعة/.test(s)) {
    const h = s.match(/(\d+)\s*ساعة/);
    sec += h ? Number(h[1]) * 3600 : 3600;
  }
  const m = s.match(/(\d+)\s*دق/);
  if (m) sec += Number(m[1]) * 60;
  return sec > 0 ? sec : null;
}

/**
 * استخراج قائمة من صفحة RSC: article + alt + href + صورة + عدد
 * countHints: مثل ["فصول"] أو ["محاضرات"]
 */
function parseArticleList(flight, pathPrefix, countHints = []) {
  const out = [];
  const seen = new Set();
  const nameById = new Map();
  const imgById = new Map();
  const countById = new Map();
  const imgByName = parseImageByName(flight);

  // فك كل article لوحده (أدق للصور والعدد)
  const parts = String(flight).split(/\["\$","article","(\d+)"/);
  for (let i = 1; i < parts.length; i += 2) {
    const id = Number(parts[i]);
    if (!isSaneId(id)) continue;
    const block = parts[i + 1] || "";
    const alt = block.match(/alt":"([^"]{2,120})"/);
    if (alt) nameById.set(id, alt[1].trim());
    const img = block.match(/src":"(https:\/\/thanawica\.com\/api\/media\/[^"]+)"/);
    if (img) imgById.set(id, img[1]);
    for (const hint of countHints) {
      // children":[10," فصول"]
      const m1 = block.match(new RegExp(String.raw`children":\[(\d+),"[^"]*` + hint));
      if (m1) {
        countById.set(id, Number(m1[1]));
        break;
      }
      // "children":"عدد المحاضرات" ... "children":8
      const m2 = block.match(
        new RegExp(
          String.raw`children":"[^"]*` +
            hint +
            String.raw`"[\s\S]{0,300}?"children":(\d+)`
        )
      );
      if (m2) {
        countById.set(id, Number(m2[1]));
        break;
      }
      // نص: ...محاضرات... children":8
      const m3 = block.match(
        new RegExp(hint + String.raw`[\s\S]{0,300}?"children":(\d+)`)
      );
      if (m3) {
        countById.set(id, Number(m3[1]));
        break;
      }
    }
  }

  const hrefRe = new RegExp(
    String.raw`href":"` + pathPrefix.replace(/\//g, "\\/") + String.raw`(\d+)"`,
    "g"
  );
  for (const m of flight.matchAll(hrefRe)) {
    const id = Number(m[1]);
    if (!isSaneId(id) || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, name: nameById.get(id) || null, image_url: null, count: null });
  }

  if (!out.length) {
    const loose = new RegExp(pathPrefix.replace(/\//g, "\\/") + String.raw`(\d+)`, "g");
    for (const m of flight.matchAll(loose)) {
      const id = Number(m[1]);
      if (!isSaneId(id) || seen.has(id)) continue;
      seen.add(id);
      out.push({ id, name: nameById.get(id) || null, image_url: null, count: null });
    }
  }

  // article keys اللي ليها اسم/عدد حتى لو href اتكرر
  for (const id of nameById.keys()) {
    if (seen.has(id)) continue;
    if (countById.has(id) || imgById.has(id)) {
      seen.add(id);
      out.push({ id, name: nameById.get(id), image_url: null, count: null });
    }
  }

  for (const row of out) {
    if (!row.name && nameById.has(row.id)) row.name = nameById.get(row.id);
    row.image_url = imgById.get(row.id) || (row.name && imgByName.get(row.name)) || null;
    if (countById.has(row.id)) row.count = countById.get(row.id);
  }

  return out;
}

function mapYearKey(yearId) {
  // Coursatk yearId 4/5 → 2027 → thanawica /years/27
  // Coursatk yearId 3 → 2026 → /years/26
  const n = Number(yearId);
  if (n === 3 || n === 26 || n === 2026) return 26;
  return 27;
}

export function isChemOrMathName(name) {
  const s = String(name || "");
  return NAME_CHEM.test(s) || NAME_MATH.test(s);
}

export function subjectKind(name) {
  const s = String(name || "");
  if (NAME_CHEM.test(s)) return "chemistry";
  if (NAME_MATH.test(s)) return "math";
  if (NAME_PHYS.test(s)) return "physics";
  if (NAME_BIO.test(s)) return "biology";
  if (NAME_AR.test(s)) return "arabic";
  if (NAME_EN.test(s)) return "english";
  if (NAME_FR.test(s)) return "french";
  if (NAME_DE.test(s)) return "german";
  return "other";
}
export function chemMathKind(name) {
  const k = subjectKind(name);
  return (k === "chemistry" || k === "math") ? k : null;
}

/** Encode Thanawica numeric id so it never collides with Coursatk ids */
export function encodeThId(n) {
  return Number(n) + 9_000_000;
}
export function decodeThId(id) {
  const n = Number(id);
  if (n >= 9_000_000 && n < 10_000_000) return n - 9_000_000;
  return null;
}
export function isThId(id) {
  return decodeThId(id) != null;
}

const cache = new Map();
function cget(k) {
  const e = cache.get(k);
  if (!e) return null;
  if (Date.now() > e.exp) {
    cache.delete(k);
    return null;
  }
  return e.v;
}
function cset(k, v, ms = 120_000) {
  cache.set(k, { v, exp: Date.now() + ms });
}

async function getHtml(urlPath) {
  await ensureLogin();
  const res = await thFetch(urlPath, { headers: { Accept: "text/html", Referer: BASE + "/" } });
  if (res.status >= 400) throw new Error(`Thanawica HTTP ${res.status} ${urlPath}`);
  return await res.text();
}

/** All subjects for a year from Thanawica */
export async function thSubjectsForYear(yearId) {
  const yk = mapYearKey(yearId);
  const ck = `subj:all:${yk}`;
  const hit = cget(ck);
  if (hit) return hit;
  const html = await getHtml(`/years/${yk}`);
  const flight = extractFlight(html) + "\n" + html;
  const imgByName = parseImageByName(flight);
  const out = [];
  const seen = new Set();
  const events = [];
  const evRe = /alt":"([^"]+)"|href":"\/subjects\/(\d+)"/g;
  let em;
  while ((em = evRe.exec(flight))) {
    if (em[1]) events.push({ type: "alt", v: em[1] });
    else if (em[2]) events.push({ type: "href", v: Number(em[2]) });
  }
  let lastAlt = null;
  for (const ev of events) {
    if (ev.type === "alt") { lastAlt = ev.v; continue; }
    if (ev.type === "href" && lastAlt) {
      const id = ev.v;
      if (!isSaneId(id) || seen.has(id)) { lastAlt = null; continue; }
      seen.add(id);
      const name = lastAlt;
      out.push({
        id: encodeThId(id), name,
        image_url: imgByName.get(name) || null,
        year_id: yearId, is_published: true,
        _source: "thanawica", _kind: subjectKind(name), _thId: id
      });
      lastAlt = null;
    }
  }
  if (!out.length) {
    const map = YEAR_SUBJECTS[yk] || YEAR_SUBJECTS[27];
    const labels = { arabic: "اللغة العربية", english: "English", chemistry: "كيمياء", physics: "فيزياء", math: "الرياضيات", french: "اللغة الفرنسية", german: "اللغة الألمانية", abilities: "القدرات", biology: "أحياء" };
    for (const [kind, sid] of Object.entries(map)) {
      if (sid == null) continue;
      out.push({ id: encodeThId(sid), name: labels[kind] || kind, image_url: null, year_id: yearId, is_published: true, _source: "thanawica", _kind: kind, _thId: sid });
    }
  }
  cset(ck, out, 5 * 60_000);
  return out;
}

export async function thTeachers(subjectId) {
  const th = decodeThId(subjectId);
  if (th == null) throw new Error("not thanawica subject");
  const ck = `teachers:${th}`;
  const hit = cget(ck);
  if (hit) return hit;
  const html = await getHtml(`/subjects/${th}`);
  const flight = extractFlight(html) + "\n" + html;
  const rows = parseArticleList(flight, "/teachers/", ["فصول", "فصل"]);
  const teachers = rows.map((r) => ({
    id: encodeThId(r.id),
    name: r.name || `مدرس ${r.id}`,
    image_url: r.image_url || null,
    subject_id: encodeThId(th),
    chapters_count: r.count != null ? r.count : null,
    count: r.count != null ? r.count : null, // توافق فرونت قديم
    _source: "thanawica",
    _thId: r.id
  }));
  cset(ck, teachers, 5 * 60_000);
  return teachers;
}

export async function thChapters(teacherId) {
  const th = decodeThId(teacherId);
  if (th == null) throw new Error("not thanawica teacher");
  const ck = `chapters:${th}`;
  const hit = cget(ck);
  if (hit) return hit;
  const html = await getHtml(`/teachers/${th}`);
  const flight = extractFlight(html) + "\n" + html;
  const rows = parseArticleList(flight, "/chapters/", ["المحاضرات", "محاضرات"]);
  const chapters = rows.map((r) => ({
    id: encodeThId(r.id),
    name: r.name || `وحدة ${r.id}`,
    image_url: r.image_url || null,
    teacher_id: encodeThId(th),
    lectures_count: r.count != null ? r.count : null,
    count: r.count != null ? r.count : null,
    _source: "thanawica",
    _thId: r.id
  }));
  cset(ck, chapters, 5 * 60_000);
  return chapters;
}

export async function thLectures(chapterId) {
  const th = decodeThId(chapterId);
  if (th == null) throw new Error("not thanawica chapter");
  const ck = `lectures:${th}`;
  const hit = cget(ck);
  if (hit) return hit;
  const html = await getHtml(`/chapters/${th}`);
  const flight = extractFlight(html) + "\n" + html;
  const rows = parseArticleList(flight, "/lectures/", ["الفيديوهات", "فيديوهات", "فيديو", "ملفات"]);

  // بطاقة المحاضرة: 2 فيديو / 3 ملفات / 1 امتحان — غالبًا بدون صورة
  const metaById = new Map();
  const parts = String(flight).split(/\["\$","article","(\d+)"/);
  for (let i = 1; i < parts.length; i += 2) {
    const id = Number(parts[i]);
    if (!isSaneId(id)) continue;
    const block = parts[i + 1] || "";
    const meta = { videos_count: null, files_count: null, exams_count: null, image_url: null };
    const img = block.match(/src":"(https:\/\/thanawica\.com\/api\/media\/[^"]+)"/);
    if (img) meta.image_url = img[1];
    const v = block.match(/children":(\d+)[\s\S]{0,120}?children":"فيديو"/);
    if (v) meta.videos_count = Number(v[1]);
    const f = block.match(/children":(\d+)[\s\S]{0,120}?children":"ملفات"/);
    if (f) meta.files_count = Number(f[1]);
    const e = block.match(/children":(\d+)[\s\S]{0,120}?children":"امتحان"/);
    if (e) meta.exams_count = Number(e[1]);
    if (meta.videos_count == null) {
      const v2 = block.match(/children":"فيديو"[\s\S]{0,80}?children":(\d+)/);
      if (v2) meta.videos_count = Number(v2[1]);
    }
    if (meta.files_count == null) {
      const f2 = block.match(/children":"ملفات"[\s\S]{0,80}?children":(\d+)/);
      if (f2) meta.files_count = Number(f2[1]);
    }
    metaById.set(id, meta);
  }

  const lectures = rows.map((r) => {
    const meta = metaById.get(r.id) || {};
    const videosCount =
      meta.videos_count != null ? meta.videos_count : r.count != null ? r.count : null;
    return {
      id: encodeThId(r.id),
      name: r.name || `محاضرة ${r.id}`,
      image_url: meta.image_url || r.image_url || null,
      chapter_id: encodeThId(th),
      videos_count: videosCount,
      files_count: meta.files_count != null ? meta.files_count : null,
      exams_count: meta.exams_count != null ? meta.exams_count : null,
      count: videosCount,
      _source: "thanawica",
      _thId: r.id
    };
  });
  cset(ck, lectures, 3 * 60_000);
  return lectures;
}

/**
 * Resolve video source from a Thanawica video page.
 * Returns { kind: "youtube", youtubeId, url } | { kind: "hls", hash } | { kind: "mp4", id }
 */
export async function thResolveVideo(lectureId, videoPageId) {
  const lec = Number(lectureId);
  const vid = String(videoPageId);
  const ck = `vsrc:${lec}:${vid}`;
  const hit = cget(ck);
  if (hit) return hit;
  await ensureLogin();
  const vhtml = await getHtml(`/lectures/${lec}/videos/${vid}`);
  const vf = extractFlight(vhtml) + "\n" + vhtml;

  // يوتيوب (embed / watch / nocookie) — قبل HLS/MP4
  const yt =
    vf.match(/(?:youtube(?:-nocookie)?\.com\/(?:embed\/|watch\?[^"'\s]*v=)|youtu\.be\/)([A-Za-z0-9_-]{6,})/i);
  if (yt) {
    const youtubeId = yt[1];
    const out = {
      kind: "youtube",
      youtubeId,
      url: "https://www.youtube.com/watch?v=" + youtubeId
    };
    cset(ck, out, 10 * 60_000);
    return out;
  }

  const pm = vf.match(/\/api\/stream\/playlist\/([a-f0-9]{16,})/i);
  if (pm) {
    const out = { kind: "hls", hash: pm[1] };
    cset(ck, out, 10 * 60_000);
    return out;
  }

  const vm = vf.match(/\/api\/videos\/([a-f0-9]{16,})/i);
  if (vm) {
    const out = { kind: "mp4", id: vm[1] };
    cset(ck, out, 10 * 60_000);
    return out;
  }

  throw new Error("مفيش مصدر فيديو للفيديو ده على ثناويكا");
}

/** توافق خلفي: يرجع hash الـ HLS فقط */
export async function thResolvePlaylistHash(lectureId, videoPageId) {
  const src = await thResolveVideo(lectureId, videoPageId);
  if (src.kind === "hls") return src.hash;
  if (src.kind === "youtube") {
    const e = new Error("الفيديو ده على يوتيوب");
    e.status = 400;
    e.youtube = src;
    throw e;
  }
  throw new Error("الفيديو ده MP4 مش playlist — استخدم thResolveVideo");
}

/** يجيب رابط MP4 موقّع من /api/videos/{id} (redirect → video.thanawica.com) */
export async function thResolveMp4Url(videoFileId) {
  await ensureLogin();
  const id = String(videoFileId).replace(/[^a-f0-9]/gi, "");
  if (id.length < 16) throw new Error("معرّف فيديو ثناويكا غير صالح");
  const res = await thFetch(`/api/videos/${id}`, {
    headers: { Accept: "*/*", Referer: BASE + "/" }
  });
  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get("location");
    if (!loc) throw new Error("ثناويكا رجّعت redirect من غير location");
    return loc.startsWith("http") ? loc : BASE + loc;
  }
  if (res.ok) {
    return BASE + `/api/videos/${id}`;
  }
  throw new Error(`فشل جلب رابط الفيديو من ثناويكا (HTTP ${res.status})`);
}

export async function thLectureContent(lectureId) {
  const th = decodeThId(lectureId);
  if (th == null) throw new Error("not thanawica lecture");
  const html = await getHtml(`/lectures/${th}`);
  const flight = extractFlight(html) + "\n" + html;

  // lecture title — فضّل عناوين عربية مش junk UI
  let lecName = `محاضرة ${th}`;
  const junk = /مشاهدة|رجوع|اختر|عدد|جار|\$L|تسجيل|تنزيل|فتح الملف|ملفات|امتحان|فيديو/;
  for (const m of flight.matchAll(/children":"([^"]{5,120})"/g)) {
    const t = m[1].trim();
    if (!junk.test(t) && /[\u0600-\u06FF]/.test(t) && t.length > 4) {
      lecName = t;
      break;
    }
  }
  // alt على الصفحة غالبًا عنوان الحصة
  for (const m of flight.matchAll(/alt":"([^"]{3,100})"/g)) {
    const t = m[1].trim();
    if (!junk.test(t) && /[\u0600-\u06FF]/.test(t)) {
      lecName = t;
      break;
    }
  }

  // أسماء الفيديوهات من h3 قبل رابط الفيديو: "شرح" / "حل الواجب"
  const videoTitleById = new Map();
  for (const m of flight.matchAll(
    /\["\$","h3"[^\]]*\{[^}]*"children":"([^"]{1,120})"\}[\s\S]{0,1500}?\/lectures\/\d+\/videos\/(\d+)/g
  )) {
    const title = m[1].trim();
    const vid = m[2];
    if (title && !/مشاهدة|رجوع|تنزيل|فتح/.test(title)) videoTitleById.set(vid, title);
  }

  // المدد: "ساعة و35 دقيقة" قبل رابط الفيديو
  const videoDurById = new Map();
  for (const m of flight.matchAll(
    /((?:ساعتين|ساعة(?:\s*و\s*\d+)?|\d+\s*ساعات?)(?:\s*و?\s*\d+\s*)?دقيقة|\d+\s*دقائق?)[\s\S]{0,1200}?\/lectures\/\d+\/videos\/(\d+)/g
  )) {
    const sec = parseArabicDuration(m[1]);
    if (sec) videoDurById.set(m[2], sec);
  }
  // fallback أوسع
  for (const m of flight.matchAll(/\/lectures\/\d+\/videos\/(\d+)/g)) {
    const vid = m[1];
    if (videoDurById.has(vid)) continue;
    const idx = m.index ?? flight.indexOf(m[0]);
    const before = flight.slice(Math.max(0, idx - 1500), idx);
    const dm = before.match(
      /((?:ساعتين|ساعة(?:\s*و\s*\d+)?|\d+\s*ساعات?)[^\n"]{0,20}دقيقة|\d+\s*دقائق?)\s*"?\s*\]/
    );
    if (dm) {
      const sec = parseArabicDuration(dm[1]);
      if (sec) videoDurById.set(vid, sec);
    }
  }

  const videos = [];
  const seen = new Set();
  for (const m of flight.matchAll(/\/lectures\/\d+\/videos\/(\d+)/g)) {
    const vid = m[1];
    if (seen.has(vid)) continue;
    seen.add(vid);
    const vName =
      videoTitleById.get(vid) ||
      (lecName && !/^محاضرة \d+$/.test(lecName) ? lecName : `فيديو ${vid}`);
    const dur = videoDurById.get(vid) || null;
    videos.push({
      id: `thv_${vid}`,
      name: vName,
      title: vName,
      type: "video",
      duration: dur,
      duration_seconds: dur,
      _source: "thanawica",
      _videoPageId: vid,
      _lectureId: th
    });
  }

  // hashes / mp4 ids already on lecture page
  const pageHashes = [...flight.matchAll(/\/api\/stream\/playlist\/([a-f0-9]{16,})/gi)].map((m) => m[1]);
  const pageMp4 = [...flight.matchAll(/\/api\/videos\/([a-f0-9]{16,})/gi)].map((m) => m[1]);
  if (pageHashes.length && videos.length === 1) {
    videos[0]._playlistHash = pageHashes[0];
    videos[0]._kind = "hls";
  } else if (pageMp4.length && videos.length === 1) {
    videos[0]._mp4Id = pageMp4[0];
    videos[0]._kind = "mp4";
  }

  // Resolve missing sources for every video (critical for play)
  for (let i = 0; i < videos.length; i++) {
    const v = videos[i];
    if (v._playlistHash || v._mp4Id) continue;
    try {
      const src = await thResolveVideo(th, v._videoPageId);
      if (src.kind === "youtube") {
        v._kind = "youtube";
        v._youtubeId = src.youtubeId;
        v.youtube_url = src.url;
        v.type = "youtube";
      } else if (src.kind === "hls") {
        v._playlistHash = src.hash;
        v._kind = "hls";
      } else if (src.kind === "mp4") {
        v._mp4Id = src.id;
        v._kind = "mp4";
      }
    } catch (e) {
      console.warn("[thanawica] video resolve", v._videoPageId, e.message);
    }
  }

  // Prefer playable ids: thp_ HLS | thm_ MP4 | thy_ YouTube
  for (const v of videos) {
    if (v._kind === "youtube" && v._youtubeId) {
      v.id = `thy_${v._youtubeId}`;
      v.youtube_url = v.youtube_url || ("https://www.youtube.com/watch?v=" + v._youtubeId);
      v.type = "youtube";
    } else if (v._playlistHash) {
      v.id = `thp_${v._playlistHash}`;
    } else if (v._mp4Id) {
      v.id = `thm_${v._mp4Id}`;
    }
    if (!v.name || /^فيديو \d+$/.test(v.name) || /^محاضرة \d+$/.test(v.name)) {
      v.name = (videoTitleById.get(v._videoPageId) || lecName || "فيديو");
    }
    v.title = v.name;
  }

  // If no video links but a bare playlist/mp4 exists
  if (!videos.length && pageHashes.length) {
    videos.push({
      id: `thp_${pageHashes[0]}`,
      name: lecName || "فيديو",
      title: lecName || "فيديو",
      type: "video",
      _source: "thanawica",
      _kind: "hls",
      _playlistHash: pageHashes[0],
      _lectureId: th
    });
  } else if (!videos.length && pageMp4.length) {
    videos.push({
      id: `thm_${pageMp4[0]}`,
      name: lecName || "فيديو",
      title: lecName || "فيديو",
      type: "video",
      _source: "thanawica",
      _kind: "mp4",
      _mp4Id: pageMp4[0],
      _lectureId: th
    });
  }

  // ملفات PDF / ملازم — من h3 + رابط التحميل
  const files = [];
  const seenFile = new Set();
  for (const m of flight.matchAll(
    /"children":"([^"]{2,150})"[\s\S]{0,600}?href":"(\/api\/media\/files\/(?:download\/)?[a-f0-9]+\.pdf)"/gi
  )) {
    const name = m[1].trim();
    let href = m[2];
    if (/تنزيل الملف|فتح الملف|ملفات المحاضرة|مشاهدة|رجوع/.test(name)) continue;
    const hash = (href.match(/([a-f0-9]{16,}\.pdf)/i) || [])[1];
    if (!hash || seenFile.has(hash)) continue;
    seenFile.add(hash);
    const url = href.startsWith("http") ? href : BASE + href.replace(/\/download\//, "/");
    // رابط مباشر للملف (عام على ثناويكا) + نسخة download
    const direct = `${BASE}/api/media/files/${hash}`;
    files.push({
      id: `thf_${hash.replace(/\.pdf$/i, "")}`,
      name,
      title: name,
      type: "pdf",
      url: direct,
      download_url: `${BASE}/api/media/files/download/${hash}`,
      _source: "thanawica"
    });
  }
  // fallback: أي PDF من غير عنوان
  if (!files.length) {
    for (const m of flight.matchAll(/\/api\/media\/files\/(?:download\/)?([a-f0-9]+\.pdf)/gi)) {
      const hash = m[1];
      if (seenFile.has(hash)) continue;
      seenFile.add(hash);
      files.push({
        id: `thf_${hash.replace(/\.pdf$/i, "")}`,
        name: hash,
        title: hash,
        type: "pdf",
        url: `${BASE}/api/media/files/${hash}`,
        download_url: `${BASE}/api/media/files/download/${hash}`,
        _source: "thanawica"
      });
    }
  }

  return {
    success: true,
    data: {
      id: encodeThId(th),
      name: lecName,
      videos,
      files,
      _source: "thanawica"
    }
  };
}

// ─── Stream: playlist + WASM decrypt ─────────────────────────
let wasmApi = null;
// قفل لكل slot — يمنع تداخل storeKey/decrypt بين فيديوهات متزامنة
const slotLocks = new Map(); // slot -> Promise
function withSlotLock(slot, fn) {
  const prev = slotLocks.get(slot) || Promise.resolve();
  let release;
  const gate = new Promise((r) => { release = r; });
  slotLocks.set(slot, prev.then(() => gate));
  return prev.then(fn).finally(() => release());
}


async function loadWasm() {
  if (wasmApi) return wasmApi;
  const wasmPath = [
    path.join(__dirname, "thanawica_decrypt.wasm"),
    path.join(__dirname, "decrypt.wasm"),
    path.join(process.cwd(), "thanawica_decrypt.wasm")
  ].find((p) => fs.existsSync(p));
  if (!wasmPath) throw new Error("thanawica_decrypt.wasm missing");
  const bytes = fs.readFileSync(wasmPath);
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const wasm = instance.exports;
  let cachedU8 = null;
  let cachedDV = null;
  let VEC_LEN = 0;
  const memU8 = () => {
    if (!cachedU8 || cachedU8.buffer !== wasm.memory.buffer) cachedU8 = new Uint8Array(wasm.memory.buffer);
    return cachedU8;
  };
  const memDV = () => {
    if (!cachedDV || cachedDV.buffer !== wasm.memory.buffer) cachedDV = new DataView(wasm.memory.buffer);
    return cachedDV;
  };
  const pass = (arr) => {
    const ptr = wasm.__wbindgen_export(arr.length, 1) >>> 0;
    memU8().set(arr, ptr);
    VEC_LEN = arr.length;
    return ptr;
  };
  wasmApi = {
    storeKey(slot, mapKey, sessionKey) {
      const p0 = pass(mapKey);
      const l0 = VEC_LEN;
      const p1 = pass(sessionKey);
      const l1 = VEC_LEN;
      return wasm.r(slot, p0, l0, p1, l1) >>> 0;
    },
    decrypt(slot, cipher, iv) {
      const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
      try {
        const p0 = pass(cipher);
        const l0 = VEC_LEN;
        const p1 = pass(iv);
        const l1 = VEC_LEN;
        wasm.d(retptr, slot, p0, l0, p1, l1);
        const r0 = memDV().getInt32(retptr, true);
        const r1 = memDV().getInt32(retptr + 4, true);
        const out = memU8().subarray(r0, r0 + r1).slice();
        try {
          wasm.__wbindgen_export2(r0, r1, 1);
        } catch {}
        return out;
      } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
      }
    }
  };
  return wasmApi;
}

function hexToBytes(hex) {
  const h = String(hex).replace(/^0x/i, "");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function stripPkcs7(buf) {
  if (!buf.length) return buf;
  const pad = buf[buf.length - 1];
  if (pad < 1 || pad > 16 || pad > buf.length) return buf;
  for (let i = buf.length - pad; i < buf.length; i++) if (buf[i] !== pad) return buf;
  return buf.subarray(0, buf.length - pad);
}

function fixTS(buf) {
  buf = stripPkcs7(buf);
  if (buf.length >= 376 && buf[0] === 0x47 && buf[188] === 0x47) return Buffer.from(buf);
  const limit = Math.min(buf.length - 376, 4512);
  for (let r = 1; r <= limit; r++) {
    if (buf[r] === 0x47 && buf[r + 188] === 0x47) {
      const i = r + 376;
      if (!(i < buf.length) || buf[i] === 0x47) return Buffer.from(buf.subarray(r));
    }
  }
  return Buffer.from(buf);
}

/**
 * Build decrypted HLS source for a Thanawica playlist hash.
 * Returns { mode, videoId, playlist, plainKey: null, segs, thMeta }
 * Playlist uses SID_TOKEN placeholders for segment URLs via our proxy.
 */
export async function thGetVideoSource(playlistHash, { sidToken = "__SID__" } = {}) {
  await ensureLogin();
  const api = await loadWasm();

  // master
  const masterRes = await thFetch(`/api/stream/playlist/${playlistHash}`, {
    headers: { Accept: "*/*", Referer: BASE + "/" }
  });
  if (!masterRes.ok) throw new Error(`playlist master HTTP ${masterRes.status}`);
  const masterText = await masterRes.text();
  // pick first variant
  const varMatch = masterText.match(/\/api\/stream\/playlist\/[a-f0-9]+\/(\w+)/);
  const quality = varMatch ? varMatch[1] : "480";
  const mediaRes = await thFetch(`/api/stream/playlist/${playlistHash}/${quality}`, {
    headers: { Accept: "*/*", Referer: BASE + "/" }
  });
  if (!mediaRes.ok) throw new Error(`playlist media HTTP ${mediaRes.status}`);
  const xkm = mediaRes.headers.get("x-km");
  const xks = mediaRes.headers.get("x-ks");
  const xkv = mediaRes.headers.get("x-kv");
  if (!xkm || !xks) throw new Error("Thanawica playlist missing x-km/x-ks");
  const km = JSON.parse(Buffer.from(xkm, "base64").toString("utf8"));
  const sessionKey = hexToBytes(xks);
  // كل مفاتيح الـ map (مش أول واحد بس) — بعض الفيديوهات بتستخدم أكتر من مفتاح
  const allMapKeys = Object.entries(km).map(([name, hex]) => ({
    name,
    bytes: hexToBytes(hex)
  }));
  if (!allMapKeys.length) throw new Error("Thanawica playlist empty key map");

  // slot مخصص لكل playlist عشان فيديوهات متزامنة متدوسش على بعض
  let slot = 0;
  for (let i = 0; i < playlistHash.length; i++) slot = (slot + playlistHash.charCodeAt(i) * (i + 1)) % 16;
  api.storeKey(slot, allMapKeys[0].bytes, sessionKey);

  const mediaText = await mediaRes.text();
  const lines = mediaText.split(/\r?\n/);
  const outLines = [];
  const segs = [];
  let curIv = null;
  let seq = 0;
  const mediaSeqLine = lines.find((l) => l.startsWith("#EXT-X-MEDIA-SEQUENCE:"));
  if (mediaSeqLine) seq = parseInt(mediaSeqLine.split(":")[1], 10) || 0;
  let mediaSeq = seq;

  for (const line of lines) {
    const t = line.trim();
    if (t.startsWith("#EXT-X-KEY:")) {
      const ivm = t.match(/IV=0x([0-9A-Fa-f]+)/i);
      curIv = ivm ? ivm[1] : null;
      // strip key line — we decrypt server-side
      continue;
    }
    if (t && !t.startsWith("#")) {
      const iv = curIv || null;
      const meta = {
        u: t.startsWith("http") ? t : BASE + t.split("?")[0],
        iv,
        s: seq,
        q: quality,
        h: playlistHash,
        v: xkv
      };
      // مسار معتم: رقم المقطع فقط — مفيش base64 فيه روابط ثناويكا
      const segIndex = segs.length;
      segs.push(meta);
      outLines.push(`/api/hls/${sidToken}/seg/${segIndex}`);
      seq++;
      continue;
    }
    outLines.push(line);
  }

  /** هل البافر يبدأ كـ MPEG-TS صالح؟ */
  function looksLikeTS(buf) {
    if (!buf || buf.length < 188) return false;
    if (buf[0] === 0x47 && buf.length >= 376 && buf[188] === 0x47) return true;
    // بعد fixTS ممكن الـ sync يتزاح
    const limit = Math.min(buf.length - 376, 2048);
    for (let r = 0; r <= limit; r++) {
      if (buf[r] === 0x47 && buf[r + 188] === 0x47) return true;
    }
    return false;
  }

  function decryptWithKey(mapKeyBytes, cipherBuf, ivHex) {
    api.storeKey(slot, mapKeyBytes, sessionKey);
    const padded = new Uint8Array(210 + cipherBuf.length);
    padded.set(cipherBuf instanceof Uint8Array ? cipherBuf : new Uint8Array(cipherBuf), 210);
    const iv = hexToBytes(ivHex || "0".repeat(32));
    const plain = api.decrypt(slot, padded, iv);
    return fixTS(plain);
  }

  return {
    mode: "thanawica",
    videoId: playlistHash,
    playlist: outLines.join("\n"),
    plainKey: Buffer.from("thanawica"), // marker — المفتاح الحقيقي جوه WASM
    defaultIv: null,
    segs,
    mediaSeq,
    allowedHosts: new Set(["thanawica.com", "www.thanawica.com"]),
    streamUrl: BASE + "/",
    thMeta: {
      playlistHash,
      quality,
      xkv,
      keyName: allMapKeys[0].name,
      keyCount: allMapKeys.length
    },
    _thWasmSlot: slot,
    _thDecrypt: async (cipherBuf, ivHex) => {
      return withSlotLock(slot, async () => {
        // جرّب كل مفتاح لحد ما يطلع TS سليم
        let last = null;
        for (const k of allMapKeys) {
          try {
            const plain = decryptWithKey(k.bytes, cipherBuf, ivHex);
            last = plain;
            if (looksLikeTS(plain)) return plain;
          } catch (e) {
            last = null;
          }
        }
        if (last) {
          console.warn("[thanawica] decrypt no valid TS for", playlistHash, "keys", allMapKeys.length);
          return last;
        }
        throw new Error("فشل فك تشفير مقطع ثناويكا");
      });
    }
  };
}

export async function thMintAndFetchSegment(meta) {
  await ensureLogin();
  // path like /api/c/{hash}/{quality}/seg_N.dat
  const u = new URL(meta.u, BASE);
  const parts = u.pathname.split("/");
  // /api/c/HASH/QUALITY/seg_X.dat
  const segName = parts[parts.length - 1];
  const hash = parts[3];
  const mintRes = await thFetch("/api/stream/mint", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      Origin: BASE,
      Referer: BASE + "/"
    },
    body: JSON.stringify({ videoId: hash, segName })
  });
  if (!mintRes.ok) throw new Error(`mint HTTP ${mintRes.status}`);
  const mint = await mintRes.json();
  u.searchParams.set("v", meta.v || "");
  u.searchParams.set("iat", String(mint.iat));
  u.searchParams.set("tok", mint.tok);
  const segRes = await thFetch(u.toString(), {
    headers: { Accept: "*/*", Referer: BASE + "/" }
  });
  if (!segRes.ok) throw new Error(`segment HTTP ${segRes.status}`);
  return Buffer.from(await segRes.arrayBuffer());
}

export function getThanawicaSessionInfo() {
  return { code: session.code, hasCookie: !!session.cookies, exp: session.exp };
}
