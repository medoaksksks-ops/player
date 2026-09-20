// Durosak Plus API V5
// Firestore = educational content
// Firebase Realtime Database = student accounts + devices + stats + bans
// All private API routes require a short-lived Bearer token.
// Admin credentials are NEVER hard-coded; configure them in Railway variables.
//
// V5 additions:
//   - Dashboard statistics
//   - Anti-scraping / bot detection
//   - Login: max 5 failed attempts / 15 min, then 30-min lock
//   - Video proxy: stream passes through our server
//   - Video tokens: 3-hour TTL, per-video, per-device
//   - Public video IDs (HMAC) so real Firestore IDs never leak

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.API_JWT_SECRET || '';
const VIDEO_TOKEN_SECRET = process.env.VIDEO_TOKEN_SECRET || JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const RTDB_URL = String(process.env.FIREBASE_RTDB_URL || 'https://english-73376-default-rtdb.firebaseio.com').replace(/\/$/, '');

const STUDENTS_PATH = 'Durosak Student';
const REVOKED_PATH = 'Durosak RevokedTokens';
const AUDIT_PATH = 'Durosak AuditLog';
const STATS_PATH = 'Durosak Stats';
const ATTEMPTS_PATH = 'Durosak LoginAttempts';
const BANS_PATH = 'Durosak Bans';
const VIDEO_TOKENS_PATH = 'Durosak VideoTokens';

const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
const ACCESS_TTL_SECONDS = Math.min(Math.max(Number(process.env.ACCESS_TTL_SECONDS) || 1800, 300), 3600);
const VIDEO_TOKEN_TTL = Math.min(Math.max(Number(process.env.VIDEO_TOKEN_TTL) || 10800, 300), 21600);
const MAX_DEVICES_DEFAULT = Math.min(Math.max(Number(process.env.MAX_DEVICES_DEFAULT) || 1, 1), 20);
const MAX_PARENT_IDS = 50;
const DEBUG_ERRORS = process.env.DEBUG_ERRORS === 'true';

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_LOCK_MS = 30 * 60 * 1000;
const SUSPICIOUS_SCORE_LIMIT = 10;

const VIDEO_HOSTS = String(process.env.VIDEO_ALLOWED_HOSTS || '')
  .split(',').map(x => x.trim()).filter(Boolean);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (!ALLOWED_ORIGINS.length) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS_ORIGIN_NOT_ALLOWED'));
  },
  methods: ['GET','POST','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Device-Id','X-Video-Token','Range']
}));
app.use(express.json({ limit: '256kb' }));

const generalLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 180,
  standardHeaders: 'draft-8', legacyHeaders: false,
  message: { success:false, error:'RATE_LIMITED', message:'Too many requests.' }
});
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, limit: 15,
  standardHeaders: 'draft-8', legacyHeaders: false,
  message: { success:false, error:'AUTH_RATE_LIMITED', message:'Too many authentication attempts.' }
});
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, limit: 5,
  standardHeaders: 'draft-8', legacyHeaders: false,
  keyGenerator: (req) => String(req.headers['x-device-id'] || req.ip),
  message: { success:false, error:'LOGIN_RATE_LIMITED', message:'Too many login attempts.' }
});
app.use(generalLimiter);

// ---------------- Utilities ----------------
function fail(res, status, error, message) {
  return res.status(status).json({ success:false, error, message });
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  const len = Math.max(x.length, y.length, 1);
  const xp = Buffer.alloc(len); x.copy(xp);
  const yp = Buffer.alloc(len); y.copy(yp);
  return crypto.timingSafeEqual(xp, yp) && x.length === y.length;
}

function randomId(bytes = 16) { return crypto.randomBytes(bytes).toString('hex'); }
function sixDigitCode(v) { return /^\d{6}$/.test(String(v || '')); }

function safeId(v, label = 'id') {
  const x = String(v ?? '').trim();
  if (!x || x.length > 200 || /[\u0000-\u001F]/.test(x)) throw new Error(`INVALID_${label.toUpperCase()}`);
  return x;
}

function parseJsonEnv(name) {
  const raw = process.env[name]; if (!raw) return null;
  try { return JSON.parse(raw); } catch (_) {
    try { return JSON.parse(Buffer.from(raw, 'base64').toString('utf8')); } catch (__) { return null; }
  }
}

function hashSecret(value, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) =>
    crypto.scrypt(String(value), salt, 64, { N: 16384, r: 8, p: 1 }, (e, d) =>
      e ? reject(e) : resolve(`${salt}:${d.toString('hex')}`)));
}
function verifySecret(value, stored) {
  return new Promise((resolve, reject) => {
    const [salt, expected] = String(stored || '').split(':');
    if (!salt || !expected) return resolve(false);
    crypto.scrypt(String(value), salt, 64, { N: 16384, r: 8, p: 1 }, (e, d) => {
      if (e) return reject(e);
      resolve(safeEqual(d.toString('hex'), expected));
    });
  });
}

function codeLookup(code) {
  if (!JWT_SECRET) throw new Error('API_JWT_SECRET_NOT_CONFIGURED');
  return crypto.createHmac('sha256', JWT_SECRET).update(`student-code:${code}`).digest('hex');
}

function b64(v) { return Buffer.from(v).toString('base64url'); }
function signToken(payload) {
  const h = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64(JSON.stringify(payload));
  const s = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${s}`;
}
function verifyToken(token) {
  const a = String(token || '').split('.');
  if (a.length !== 3 || !JWT_SECRET) return null;
  const [h, p, s] = a;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
  if (!safeEqual(s, expected)) return null;
  try {
    const x = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (!x.exp || x.exp <= Math.floor(Date.now() / 1000)) return null;
    return x;
  } catch (_) { return null; }
}
function bearer(req) {
  const h = String(req.headers.authorization || '');
  return h.startsWith('Bearer ') ? h.slice(7).trim() : '';
}

async function audit(req, action, details = {}) {
  try {
    const entry = {
      action,
      admin: req.auth?.sub || null,
      ip: req.ip || null,
      userAgent: String(req.headers['user-agent'] || '').slice(0, 200),
      at: Date.now(),
      ...details
    };
    await rtdbPath(`${encodeURIComponent(AUDIT_PATH)}.json`, { method: 'POST', body: entry });
  } catch (e) { console.error('[audit] failed', e.message); }
}

// ---------------- Firebase / Firestore ----------------
let db = null; let firebaseMode = null;
function initFirebase() {
  const service = parseJsonEnv('FIREBASE_ADMIN_SERVICE_ACCOUNT_JSON');
  if (service?.type === 'service_account' && service.private_key && service.client_email) {
    try {
      if (!admin.apps.length) admin.initializeApp({
        credential: admin.credential.cert(service),
        databaseURL: RTDB_URL
      });
      db = admin.firestore();
      firebaseMode = 'admin';
      console.log('Firestore Admin + RTDB connected');
      return;
    } catch (e) { console.error('Firestore init failed:', e.message); }
  }
  const web = parseJsonEnv('FIREBASE_SERVICE_ACCOUNT_JSON');
  if (web?.apiKey && web?.projectId) {
    try {
      const fa = require('firebase/app');
      const fs = require('firebase/firestore');
      const client = fa.initializeApp(web);
      db = fs.getFirestore(client);
      firebaseMode = 'web';
      console.log('Firestore Web Config connected');
    } catch (e) { console.error('Firestore Web init failed:', e.message); }
  }
}
initFirebase();

function needDb(res) {
  if (db) return true;
  fail(res, 503, 'FIREBASE_NOT_CONFIGURED', 'Firestore is not configured.');
  return false;
}
function contentQuery(parentId) {
  if (firebaseMode === 'web') {
    const fs = require('firebase/firestore');
    return fs.getDocs(fs.query(fs.collection(db, 'content'), fs.where('parentId', '==', parentId)));
  }
  return db.collection('content').where('parentId', '==', parentId).get();
}
function contentDoc(id) {
  if (firebaseMode === 'web') {
    const fs = require('firebase/firestore');
    return fs.getDoc(fs.doc(db, 'content', id));
  }
  return db.collection('content').doc(id).get();
}
function serialize(v) {
  if (v === null || v === undefined) return v;
  if (v?.toDate instanceof Function) return v.toDate().toISOString();
  if (Array.isArray(v)) return v.map(serialize);
  if (typeof v === 'object') { const o = {}; for (const [k, x] of Object.entries(v)) o[k] = serialize(x); return o; }
  return v;
}
function docToItem(doc) { return { id: doc.id, data: serialize(doc.data() || {}) }; }
function parseParentIds(v) {
  const arr = Array.isArray(v) ? v : [v];
  const out = [];
  for (const x of arr) {
    if (x === undefined || x === null || x === '') continue;
    for (const p of String(x).split(',').map(s => s.trim()).filter(Boolean)) out.push(safeId(p, 'parent_id'));
  }
  const unique = [...new Set(out)];
  if (unique.length > MAX_PARENT_IDS) throw new Error('TOO_MANY_PARENT_IDS');
  return unique;
}

// ---------------- Realtime Database ----------------
async function rtdbPath(path, options = {}) {
  if (firebaseMode === 'admin' && admin.apps.length) {
    const raw = String(path);
    const [pathname, queryString = ''] = raw.split('?');
    const clean = pathname.replace(/\.json$/, '').replace(/^\/+|\/+$/g, '');
    let ref = admin.database().ref(clean.split('/').filter(Boolean).map(decodeURIComponent).join('/'));
    const params = new URLSearchParams(queryString);
    if (params.has('orderBy')) ref = ref.orderByChild(JSON.parse(params.get('orderBy')));
    if (params.has('equalTo')) ref = ref.equalTo(JSON.parse(params.get('equalTo')));
    if (params.has('limitToFirst')) ref = ref.limitToFirst(Number(params.get('limitToFirst')));
    const method = (options.method || 'GET').toUpperCase();
    if (method === 'GET') { const snap = await ref.once('value'); return snap.val(); }
    if (method === 'POST') { const pushed = ref.push(); await pushed.set(options.body); return { name: pushed.key }; }
    if (method === 'PATCH') { await ref.update(options.body || {}); return null; }
    if (method === 'PUT') { await ref.set(options.body); return null; }
    if (method === 'DELETE') { await ref.remove(); return null; }
    throw new Error(`RTDB_METHOD_${method}`);
  }
  const raw = String(path);
  const [pathname, query = ''] = raw.split('?');
  const slash = pathname.startsWith('/') ? '' : '/';
  const normalized = pathname.endsWith('.json') ? pathname : `${pathname}.json`;
  const url = `${RTDB_URL}${slash}${normalized}${query ? '?' + query : ''}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, {
      method: options.method || 'GET',
      headers: { 'Content-Type': 'application/json' },
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: controller.signal
    });
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
    if (!response.ok) {
      const e = new Error(`RTDB_${response.status}`);
      e.status = response.status; e.body = data;
      throw e;
    }
    return data;
  } finally { clearTimeout(timer); }
}

async function getStudentByLookup(lookup) {
  const path = `${encodeURIComponent(STUDENTS_PATH)}.json?orderBy=%22codeLookup%22&equalTo=${encodeURIComponent(JSON.stringify(lookup))}&limitToFirst=1`;
  const data = await rtdbPath(path);
  if (!data || typeof data !== 'object') return null;
  const e = Object.entries(data)[0];
  return e ? { id: e[0], data: e[1] || {} } : null;
}
async function getStudent(id) {
  return await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`);
}

// ---------------- Token revocation ----------------
async function isRevoked(jti) {
  if (!jti) return false;
  try {
    const v = await rtdbPath(`${encodeURIComponent(REVOKED_PATH)}/${encodeURIComponent(jti)}.json`);
    return Boolean(v);
  } catch (_) { return false; }
}
async function revokeToken(jti, ttlSeconds) {
  if (!jti) return;
  await rtdbPath(`${encodeURIComponent(REVOKED_PATH)}/${encodeURIComponent(jti)}.json`, {
    method: 'PUT',
    body: { revokedAt: Date.now(), expiresAt: Date.now() + ttlSeconds * 1000 }
  });
}

// ---------------- Bot / Scraper Detection ----------------
function computeSuspicionScore(req, extra = {}) {
  let score = 0;
  const ua = String(req.headers['user-agent'] || '');
  const acc = String(req.headers['accept'] || '');
  const accLang = String(req.headers['accept-language'] || '');

  if (!ua || ua.length < 10) score += 3;
  if (/curl|wget|python|node|axios|postman|scrapy|bot|spider|crawler|httpclient|java|okhttp/i.test(ua)) score += 5;
  if (!acc || acc === '*/*') score += 2;
  if (!accLang) score += 1;
  if (!req.headers.origin && !req.headers.referer && /mozilla|chrome|safari|firefox/i.test(ua)) score += 2;

  const did = String(extra.deviceId || req.headers['x-device-id'] || '');
  if (!did) score += 2;

  return score;
}

async function recordLoginAttempt(key, success) {
  const now = Date.now();
  const path = `${encodeURIComponent(ATTEMPTS_PATH)}/${encodeURIComponent(key)}.json`;
  const current = await rtdbPath(path).catch(() => null) || {};
  const attempts = Array.isArray(current.attempts) ? current.attempts : [];
  const fresh = attempts.filter(t => now - t < LOGIN_WINDOW_MS);
  fresh.push({ at: now, ok: !!success });
  const failed = fresh.filter(t => !t.ok).length;
  await rtdbPath(path, { method: 'PUT', body: { attempts: fresh, failedCount: failed, updatedAt: now } }).catch(() => {});
  return { failed, total: fresh.length };
}
async function getFailedAttempts(key) {
  const path = `${encodeURIComponent(ATTEMPTS_PATH)}/${encodeURIComponent(key)}.json`;
  const current = await rtdbPath(path).catch(() => null);
  if (!current || !Array.isArray(current.attempts)) return 0;
  const now = Date.now();
  return current.attempts.filter(t => !t.ok && (now - t.at) < LOGIN_WINDOW_MS).length;
}
async function clearLoginAttempts(key) {
  const path = `${encodeURIComponent(ATTEMPTS_PATH)}/${encodeURIComponent(key)}.json`;
  await rtdbPath(path, { method: 'DELETE' }).catch(() => {});
}
async function isBanned(scope, id) {
  if (!id) return false;
  const v = await rtdbPath(`${encodeURIComponent(BANS_PATH)}/${encodeURIComponent(scope)}/${encodeURIComponent(id)}.json`).catch(() => null);
  if (!v) return false;
  if (v.until && v.until < Date.now()) return false;
  return true;
}
async function ban(scope, id, reason, durationMs = 24 * 60 * 60 * 1000) {
  const until = Date.now() + durationMs;
  await rtdbPath(`${encodeURIComponent(BANS_PATH)}/${encodeURIComponent(scope)}/${encodeURIComponent(id)}.json`, {
    method: 'PUT', body: { reason, bannedAt: Date.now(), until }
  }).catch(() => {});
}

// ---------------- Stats ----------------
async function incrStat(field, amount = 1) {
  try {
    const path = `${encodeURIComponent(STATS_PATH)}/${field}.json`;
    const current = Number(await rtdbPath(path).catch(() => 0)) || 0;
    await rtdbPath(path, { method: 'PUT', body: current + amount }).catch(() => {});
  } catch (_) {}
}
async function pushDailyStat(prefix, amount = 1) {
  const day = new Date().toISOString().slice(0, 10);
  const path = `${encodeURIComponent(STATS_PATH)}/daily/${day}/${prefix}.json`;
  const current = Number(await rtdbPath(path).catch(() => 0)) || 0;
  await rtdbPath(path, { method: 'PUT', body: current + amount }).catch(() => {});
}

// ---------------- Video helpers ----------------
function signVideoToken(payload) {
  const h = b64(JSON.stringify({ alg: 'HS256', typ: 'VIDEO' }));
  const p = b64(JSON.stringify(payload));
  const s = crypto.createHmac('sha256', VIDEO_TOKEN_SECRET).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${s}`;
}
function verifyVideoToken(token) {
  const a = String(token || '').split('.');
  if (a.length !== 3 || !VIDEO_TOKEN_SECRET) return null;
  const [h, p, s] = a;
  const expected = crypto.createHmac('sha256', VIDEO_TOKEN_SECRET).update(`${h}.${p}`).digest('base64url');
  if (!safeEqual(s, expected)) return null;
  try {
    const x = JSON.parse(Buffer.from(p, 'base64url').toString());
    if (!x.exp || x.exp <= Math.floor(Date.now() / 1000)) return null;
    if (x.typ !== 'video') return null;
    return x;
  } catch (_) { return null; }
}
function publicVideoId(firestoreId) {
  return crypto.createHmac('sha256', VIDEO_TOKEN_SECRET).update(`vid:${firestoreId}`).digest('hex').slice(0, 24);
}
async function isVideoTokenRevoked(jti) {
  if (!jti) return false;
  const v = await rtdbPath(`${encodeURIComponent(VIDEO_TOKENS_PATH)}/revoked/${encodeURIComponent(jti)}.json`).catch(() => null);
  return Boolean(v);
}
async function revokeVideoToken(jti, ttl) {
  await rtdbPath(`${encodeURIComponent(VIDEO_TOKENS_PATH)}/revoked/${encodeURIComponent(jti)}.json`, {
    method: 'PUT', body: { revokedAt: Date.now(), expiresAt: Date.now() + ttl * 1000 }
  }).catch(() => {});
}

// ---------------- Auth middleware ----------------
async function requireStudent(req, res, next) {
  const p = verifyToken(bearer(req));
  if (!p || p.role !== 'student' || !p.sub)
    return fail(res, 401, 'UNAUTHORIZED', 'Valid student Bearer token required.');
  if (await isRevoked(p.jti))
    return fail(res, 401, 'TOKEN_REVOKED', 'Token has been revoked.');
  try {
    const student = await getStudent(p.sub);
    if (!student) return fail(res, 401, 'STUDENT_NOT_FOUND', 'Student not found.');
    if (student.status === 'disabled' || student.status === 'deleted')
      return fail(res, 403, 'ACCOUNT_DISABLED', 'Account is disabled.');
    if (Number(student.expiresAt || 0) <= Date.now())
      return fail(res, 403, 'ACCOUNT_EXPIRED', 'Account has expired.');
    req.auth = p;
    req.student = student;
    next();
  } catch (e) {
    console.error('[requireStudent]', e);
    return fail(res, 500, 'AUTH_CHECK_FAILED', 'Unable to verify account.');
  }
}
async function requireAdmin(req, res, next) {
  const p = verifyToken(bearer(req));
  if (!p || p.role !== 'admin' || !p.sub)
    return fail(res, 401, 'ADMIN_UNAUTHORIZED', 'Valid admin Bearer token required.');
  if (await isRevoked(p.jti))
    return fail(res, 401, 'TOKEN_REVOKED', 'Token has been revoked.');
  req.auth = p;
  next();
}

// ---------------- Root / Health ----------------
app.get('/', (req, res) => res.json({
  success: true, name: 'Durosak Plus API', version: 'v5',
  security: 'bearer-token-protected', firestore: firebaseMode, rtdb: true, videoProxy: true
}));
app.get('/health', (req, res) => res.json({
  success: true, firestoreConfigured: Boolean(db), firestoreMode: firebaseMode,
  rtdbConfigured: Boolean(RTDB_URL), time: new Date().toISOString()
}));

// ---------------- Admin login ----------------
app.post('/api/admin/login', authLimiter, async (req, res) => {
  if (!JWT_SECRET || !ADMIN_USERNAME || !ADMIN_PASSWORD)
    return fail(res, 503, 'ADMIN_AUTH_NOT_CONFIGURED', 'Admin authentication is not configured.');
  const username = String(req.body?.username || '');
  const password = String(req.body?.password || '');
  if (!safeEqual(username, ADMIN_USERNAME) || !safeEqual(password, ADMIN_PASSWORD)) {
    await pushDailyStat('admin_login_failed', 1);
    return fail(res, 401, 'INVALID_ADMIN_CREDENTIALS', 'Invalid admin credentials.');
  }
  const now = Math.floor(Date.now() / 1000);
  const jti = randomId(12);
  const token = signToken({ sub: 'admin', role: 'admin', iat: now, exp: now + ACCESS_TTL_SECONDS, jti });
  await pushDailyStat('admin_logins', 1);
  res.json({ success: true, accessToken: token, expiresIn: ACCESS_TTL_SECONDS, jti, admin: { username: ADMIN_USERNAME } });
});

// ---------------- Admin logout ----------------
app.post('/api/admin/logout', requireAdmin, async (req, res) => {
  await revokeToken(req.auth.jti, ACCESS_TTL_SECONDS);
  await audit(req, 'admin.logout');
  res.json({ success: true, revoked: true });
});

// ---------------- Student login (5 attempts / 15 min) ----------------
app.post('/api/auth/login', authLimiter, loginLimiter, async (req, res) => {
  try {
    if (!JWT_SECRET) return fail(res, 503, 'AUTH_NOT_CONFIGURED', 'API_JWT_SECRET is not configured.');

    const code = String(req.body?.code || '').trim();
    const deviceId = String(req.body?.deviceId || req.headers['x-device-id'] || '').trim();
    const deviceName = String(req.body?.deviceName || 'Unknown').slice(0, 100);
    const ip = req.ip || 'unknown';

    if (!sixDigitCode(code)) return fail(res, 400, 'INVALID_CODE', 'Student code must contain exactly 6 digits.');
    if (!deviceId || deviceId.length < 8 || deviceId.length > 200)
      return fail(res, 400, 'INVALID_DEVICE_ID', 'A valid deviceId is required.');

    // Ban checks
    if (await isBanned('ip', ip)) {
      await pushDailyStat('logins_banned', 1);
      return fail(res, 403, 'IP_BANNED', 'Access temporarily blocked.');
    }
    if (await isBanned('device', deviceId)) {
      await pushDailyStat('logins_banned', 1);
      return fail(res, 403, 'DEVICE_BANNED', 'This device is temporarily blocked.');
    }
    if (await isBanned('code', code)) {
      await pushDailyStat('logins_banned', 1);
      return fail(res, 403, 'CODE_BANNED', 'Too many attempts. Try later.');
    }

    // Bot detection
    const suspicion = computeSuspicionScore(req, { deviceId });
    if (suspicion >= SUSPICIOUS_SCORE_LIMIT) {
      await ban('ip', ip, 'SUSPICIOUS_BOT', 6 * 60 * 60 * 1000);
      await pushDailyStat('bot_bans', 1);
      await audit(req, 'security.bot-ban', { ip, deviceId, suspicion, ua: req.headers['user-agent'] });
      return fail(res, 403, 'BLOCKED', 'Request blocked.');
    }

    // Failed attempts
    const attemptKey = `${deviceId}__${code}`;
    const failedBefore = await getFailedAttempts(attemptKey);
    if (failedBefore >= MAX_LOGIN_ATTEMPTS) {
      await ban('device', deviceId, 'TOO_MANY_FAILED_LOGINS', LOGIN_LOCK_MS);
      await pushDailyStat('lockouts', 1);
      await audit(req, 'security.login-lockout', { ip, deviceId, code, failedBefore });
      return fail(res, 429, 'LOGIN_LOCKED', 'Too many failed attempts. Try again in 30 minutes.');
    }

    const lookup = codeLookup(code);
    const found = await getStudentByLookup(lookup);

    const recordFail = async (reason) => {
      await recordLoginAttempt(attemptKey, false);
      await incrStat('failed_logins_total', 1);
      await pushDailyStat('failed_logins', 1);
      await audit(req, 'auth.login.failed', { ip, deviceId, reason });
      return fail(res, 401, 'INVALID_CREDENTIALS', 'Invalid or expired code.');
    };

    if (!found) return recordFail('no_student');

    const d = found.data;
    const expires = Number(d.expiresAt || 0);
    if (d.status === 'disabled' || d.status === 'deleted') return recordFail('disabled');
    if (expires <= Date.now()) return recordFail('expired');
    if (!(await verifySecret(code, d.codeHash))) return recordFail('bad_code');

    // Devices
    const devices = d.devices && typeof d.devices === 'object' ? d.devices : {};
    const maxDevices = Number(d.maxDevices || MAX_DEVICES_DEFAULT);
    const existing = devices[deviceId];

    if (existing && existing.status === 'blocked') {
      await audit(req, 'student.login.device-blocked', { studentId: found.id, deviceId });
      await pushDailyStat('blocked_device_attempts', 1);
      return fail(res, 403, 'DEVICE_BLOCKED', 'This device has been blocked.');
    }

    if (!existing) {
      const activeCount = Object.values(devices).filter(x => x && x.status !== 'removed').length;
      if (activeCount >= maxDevices) {
        await audit(req, 'student.login.limit', { studentId: found.id, deviceId, activeCount, maxDevices });
        return fail(res, 403, 'DEVICE_LIMIT_REACHED', `Device limit reached (${activeCount}/${maxDevices}).`);
      }
    }

    // Success
    await clearLoginAttempts(attemptKey);
    const now = Date.now();
    const deviceRecord = {
      ...(existing || {}),
      deviceId,
      name: existing?.name || deviceName,
      status: 'active',
      firstSeenAt: existing?.firstSeenAt || now,
      lastSeenAt: now,
      lastIp: ip,
      userAgent: String(req.headers['user-agent'] || '').slice(0, 200)
    };
    await rtdbPath(
      `${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(found.id)}/devices/${encodeURIComponent(deviceId)}.json`,
      { method: 'PUT', body: deviceRecord }
    );

    const nowSec = Math.floor(now / 1000);
    const jti = randomId(12);
    const token = signToken({
      sub: found.id, role: 'student', deviceId,
      iat: nowSec, exp: nowSec + ACCESS_TTL_SECONDS, jti
    });

    await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(found.id)}.json`, {
      method: 'PATCH', body: { lastLoginAt: now, lastLoginDevice: deviceId }
    });

    await incrStat('logins_total', 1);
    await pushDailyStat('logins', 1);

    return res.json({
      success: true, accessToken: token, expiresIn: ACCESS_TTL_SECONDS, jti,
      student: {
        id: found.id, name: d.name || '', status: d.status || 'active',
        expiresAt: new Date(expires).toISOString(), maxDevices,
        devicesCount: Object.values(devices).filter(x => x && x.status !== 'removed').length + (existing ? 0 : 1)
      },
      device: { id: deviceId, name: deviceRecord.name, status: 'active' }
    });
  } catch (e) {
    console.error('student login', e);
    return fail(res, 500, 'LOGIN_FAILED', 'Login failed.');
  }
});

// ---------------- Student logout ----------------
app.post('/api/auth/logout', requireStudent, async (req, res) => {
  await revokeToken(req.auth.jti, ACCESS_TTL_SECONDS);
  res.json({ success: true, revoked: true });
});

// ---------------- Student: my devices ----------------
app.get('/api/student/devices', requireStudent, async (req, res) => {
  const devices = req.student.devices || {};
  const list = Object.values(devices).map(d => ({
    deviceId: d.deviceId, name: d.name, status: d.status,
    firstSeenAt: d.firstSeenAt, lastSeenAt: d.lastSeenAt
  }));
  res.json({ success: true, maxDevices: Number(req.student.maxDevices || MAX_DEVICES_DEFAULT), count: list.length, devices: list });
});

// ---------------- Student: remove own device ----------------
app.delete('/api/student/devices/:deviceId', requireStudent, async (req, res) => {
  try {
    const deviceId = safeId(req.params.deviceId, 'device_id');
    const devices = req.student.devices || {};
    if (!devices[deviceId]) return fail(res, 404, 'DEVICE_NOT_FOUND', 'Device not found.');
    await rtdbPath(
      `${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(req.auth.sub)}/devices/${encodeURIComponent(deviceId)}.json`,
      { method: 'PATCH', body: { status: 'removed', removedAt: Date.now(), removedBy: 'student' } }
    );
    res.json({ success: true, deviceId, removed: true });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'DEVICE_REMOVE_FAILED', 'Unable to remove device.');
  }
});

// ---------------- Protected Firestore content ----------------
app.get('/api/content', requireStudent, async (req, res) => {
  if (!needDb(res)) return;
  try {
    const ids = parseParentIds(req.query.parentId ?? req.query.parentIds);
    if (!ids.length) return fail(res, 400, 'PARENT_ID_REQUIRED', 'Pass parentId.');
    const lists = await Promise.all(ids.map(async id => (await contentQuery(id)).docs.map(docToItem)));
    const items = []; const seen = new Set();
    for (const list of lists) for (const x of list) if (!seen.has(x.id)) { seen.add(x.id); items.push(x); }
    res.set('Cache-Control', 'private, no-store');
    res.json({ success: true, source: 'firestore', collection: 'content', parentIds: ids, count: items.length, items });
  } catch (e) {
    console.error(e);
    if (e.message === 'TOO_MANY_PARENT_IDS') return fail(res, 400, 'TOO_MANY_PARENT_IDS', `Max ${MAX_PARENT_IDS} parentIds.`);
    fail(res, 500, 'CONTENT_READ_FAILED', 'Unable to read content.');
  }
});

app.get('/api/content/doc/:id', requireStudent, async (req, res) => {
  if (!needDb(res)) return;
  try {
    const id = safeId(req.params.id);
    const snap = await contentDoc(id);
    const exists = typeof snap.exists === 'function' ? snap.exists() : Boolean(snap.exists);
    if (!exists) return fail(res, 404, 'CONTENT_NOT_FOUND', 'Document not found.');
    res.set('Cache-Control', 'private, no-store');
    res.json({ success: true, source: 'firestore', collection: 'content', item: docToItem(snap) });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'CONTENT_DOCUMENT_READ_FAILED', 'Unable to read document.');
  }
});

app.get('/api/content/children', requireStudent, async (req, res) => {
  if (!needDb(res)) return;
  try {
    const ids = parseParentIds(req.query.parentIds ?? req.query.parentId);
    if (!ids.length) return fail(res, 400, 'PARENT_IDS_REQUIRED', 'Pass parentIds.');
    const lists = await Promise.all(ids.map(async id => (await contentQuery(id)).docs.map(docToItem)));
    const byParentId = {}; const items = [];
    ids.forEach((id, i) => {
      byParentId[id] = lists[i];
      lists[i].forEach(x => items.push({ parentId: id, ...x }));
    });
    res.json({ success: true, parentIds: ids, count: items.length, byParentId, items });
  } catch (e) {
    console.error(e);
    if (e.message === 'TOO_MANY_PARENT_IDS') return fail(res, 400, 'TOO_MANY_PARENT_IDS', `Max ${MAX_PARENT_IDS} parentIds.`);
    fail(res, 500, 'BATCH_READ_FAILED', 'Unable to read content.');
  }
});

// ---------------- Video: issue token (3 hours) ----------------
app.post('/api/video/:publicId/token', requireStudent, async (req, res) => {
  if (!needDb(res)) return;
  try {
    const publicId = safeId(req.params.publicId, 'public_video_id');
    // Resolve video document
    let videoDoc = null;
    const byPublic = await db.collection('content').where('videoPublicId', '==', publicId).limit(1).get();
    if (!byPublic.empty) videoDoc = byPublic.docs[0];
    else {
      const direct = await contentDoc(publicId);
      const exists = typeof direct.exists === 'function' ? direct.exists() : Boolean(direct.exists);
      if (exists) videoDoc = direct;
    }
    if (!videoDoc) return fail(res, 404, 'VIDEO_NOT_FOUND', 'Video not found.');

    const nowSec = Math.floor(Date.now() / 1000);
    const jti = randomId(12);
    const token = signVideoToken({
      typ: 'video',
      sub: req.auth.sub,
      deviceId: req.auth.deviceId,
      publicId,
      iat: nowSec,
      exp: nowSec + VIDEO_TOKEN_TTL,
      jti
    });
    await incrStat('video_tokens_issued', 1);
    await pushDailyStat('video_tokens', 1);
    res.json({
      success: true,
      videoToken: token,
      expiresIn: VIDEO_TOKEN_TTL,
      streamUrl: `/api/video/stream/${publicId}?t=${token}`
    });
  } catch (e) {
    console.error('[video token]', e);
    fail(res, 500, 'VIDEO_TOKEN_FAILED', 'Unable to create video token.');
  }
});

// ---------------- Video: revoke token ----------------
app.post('/api/video/revoke', requireStudent, async (req, res) => {
  const jti = String(req.body?.jti || '');
  if (!jti) return fail(res, 400, 'JTI_REQUIRED', 'Pass jti.');
  await revokeVideoToken(jti, VIDEO_TOKEN_TTL);
  res.json({ success: true, revoked: true });
});

// ---------------- Video: stream proxy ----------------
app.get('/api/video/stream/:publicId', async (req, res) => {
  try {
    const publicId = safeId(req.params.publicId, 'public_video_id');
    const vt = String(req.query.t || req.headers['x-video-token'] || '');
    const payload = verifyVideoToken(vt);
    if (!payload || payload.publicId !== publicId)
      return fail(res, 401, 'VIDEO_UNAUTHORIZED', 'Valid video token required.');
    if (await isVideoTokenRevoked(payload.jti))
      return fail(res, 401, 'VIDEO_TOKEN_REVOKED', 'Video token revoked.');

    const student = await getStudent(payload.sub);
    if (!student || student.status === 'disabled' || student.status === 'deleted')
      return fail(res, 403, 'ACCOUNT_DISABLED', 'Account is disabled.');
    const device = student.devices?.[payload.deviceId];
    if (!device || device.status === 'blocked' || device.status === 'removed')
      return fail(res, 403, 'DEVICE_BLOCKED', 'Device is no longer allowed.');

    // Fetch video from Firestore
    let videoData = null;
    const byPublic = await db.collection('content').where('videoPublicId', '==', publicId).limit(1).get();
    if (!byPublic.empty) videoData = byPublic.docs[0].data();
    else {
      const direct = await contentDoc(publicId);
      const exists = typeof direct.exists === 'function' ? direct.exists() : Boolean(direct.exists);
      if (exists) videoData = direct.data();
    }
    if (!videoData) return fail(res, 404, 'VIDEO_NOT_FOUND', 'Video not found.');

    const videoUrl = videoData.videoUrl || videoData.url || videoData.src;
    if (!videoUrl) return fail(res, 404, 'VIDEO_URL_MISSING', 'No video URL configured.');

    let parsed;
    try { parsed = new URL(videoUrl); } catch (_) { return fail(res, 400, 'BAD_VIDEO_URL', 'Invalid video URL.'); }
    if (VIDEO_HOSTS.length && !VIDEO_HOSTS.some(h => parsed.hostname === h || parsed.hostname.endsWith('.' + h)))
      return fail(res, 403, 'VIDEO_HOST_NOT_ALLOWED', 'Video host not allowed.');

    const upstream = await fetch(videoUrl, {
      headers: {
        'User-Agent': 'Durosak-Proxy/1.0',
        'Range': req.headers.range || '',
        'Accept': '*/*'
      }
    });

    if (!upstream.ok && upstream.status !== 206)
      return fail(res, 502, 'UPSTREAM_ERROR', 'Unable to fetch video.');

    res.status(upstream.status);
    ['content-type','content-length','content-range','accept-ranges','cache-control','etag','last-modified']
      .forEach(h => { const v = upstream.headers.get(h); if (v) res.set(h, v); });
    res.set('Cache-Control', 'private, max-age=3600');
    res.set('X-Content-Type-Options', 'nosniff');

    const reader = upstream.body.getReader();
    const pump = async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!res.write(Buffer.from(value))) {
          await new Promise(r => res.once('drain', r));
        }
      }
      res.end();
    };
    pump().catch(err => { console.error('[video stream]', err); try { res.end(); } catch (_) {} });

    await incrStat('video_streams_total', 1);
    await pushDailyStat('video_streams', 1);
  } catch (e) {
    console.error('[video stream]', e);
    if (!res.headersSent) fail(res, 500, 'VIDEO_STREAM_FAILED', 'Unable to stream video.');
  }
});

// ---------------- Admin: student management ----------------
app.get('/api/admin/students', requireAdmin, async (req, res) => {
  try {
    const data = await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}.json`);
    const students = Object.entries(data || {}).map(([id, d]) => ({
      id,
      name: d?.name || '',
      status: d?.status || 'active',
      durationDays: d?.durationDays || null,
      maxDevices: Number(d?.maxDevices || MAX_DEVICES_DEFAULT),
      devicesCount: d?.devices ? Object.values(d.devices).filter(x => x && x.status !== 'removed').length : 0,
      createdAt: d?.createdAt || null,
      expiresAt: d?.expiresAt || null,
      lastLoginAt: d?.lastLoginAt || null
    }));
    students.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ success: true, storage: 'firebase-rtdb', node: STUDENTS_PATH, count: students.length, students: students.slice(0, 1000) });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'STUDENTS_READ_FAILED', 'Unable to list students.');
  }
});

app.post('/api/admin/students', requireAdmin, async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const durationDays = Number(req.body?.durationDays);
    const maxDevices = req.body?.maxDevices === undefined ? MAX_DEVICES_DEFAULT : Number(req.body.maxDevices);
    if (!name || name.length > 120) return fail(res, 400, 'INVALID_NAME', 'Invalid name.');
    if (!Number.isInteger(durationDays) || durationDays < 1 || durationDays > 3650)
      return fail(res, 400, 'INVALID_DURATION', 'durationDays must be 1..3650.');
    if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 20)
      return fail(res, 400, 'INVALID_MAX_DEVICES', 'maxDevices must be 1..20.');

    let code = '', lookup = '', existing = null;
    for (let attempt = 0; attempt < 25; attempt++) {
      code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      lookup = codeLookup(code);
      existing = await getStudentByLookup(lookup);
      if (!existing || existing.data?.status === 'deleted') break;
    }
    if (existing && existing.data?.status !== 'deleted')
      return fail(res, 503, 'CODE_GENERATION_FAILED', 'Unable to generate a unique student code. Try again.');

    const codeHash = await hashSecret(code);
    const now = Date.now();
    const expiresAt = now + durationDays * 86400000;
    const body = {
      name, codeHash, codeLookup: lookup, status: 'active',
      durationDays, maxDevices, devices: {},
      createdAt: now, expiresAt, lastLoginAt: null
    };
    const created = await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}.json`, { method: 'POST', body });
    const id = created?.name;
    if (!id) throw new Error('RTDB_CREATE_FAILED');
    await audit(req, 'student.create', { studentId: id, name, durationDays, maxDevices });
    await incrStat('students_created_total', 1);
    await pushDailyStat('students_created', 1);
    res.status(201).json({
      success: true,
      student: { id, name, code, durationDays, maxDevices, status: 'active',
        createdAt: new Date(now).toISOString(), expiresAt: new Date(expiresAt).toISOString() }
    });
  } catch (e) {
    console.error('student create', e);
    fail(res, 500, 'STUDENT_CREATE_FAILED', 'Unable to create student.');
  }
});

app.patch('/api/admin/students/:id', requireAdmin, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const current = await getStudent(id);
    if (!current) return fail(res, 404, 'STUDENT_NOT_FOUND', 'Student not found.');
    const patch = {};
    if (req.body?.name !== undefined) {
      const name = String(req.body.name).trim();
      if (!name || name.length > 120) return fail(res, 400, 'INVALID_NAME', 'Invalid name.');
      patch.name = name;
    }
    if (req.body?.status !== undefined) {
      const status = String(req.body.status);
      if (!['active', 'disabled'].includes(status)) return fail(res, 400, 'INVALID_STATUS', 'Status must be active or disabled.');
      patch.status = status;
    }
    if (req.body?.durationDays !== undefined) {
      const days = Number(req.body.durationDays);
      if (!Number.isInteger(days) || days < 1 || days > 3650) return fail(res, 400, 'INVALID_DURATION', 'Invalid duration.');
      patch.durationDays = days;
      patch.expiresAt = Date.now() + days * 86400000;
    }
    if (req.body?.maxDevices !== undefined) {
      const md = Number(req.body.maxDevices);
      if (!Number.isInteger(md) || md < 1 || md > 20) return fail(res, 400, 'INVALID_MAX_DEVICES', 'maxDevices must be 1..20.');
      patch.maxDevices = md;
    }
    if (!Object.keys(patch).length) return fail(res, 400, 'NOTHING_TO_UPDATE', 'No valid fields supplied.');
    patch.updatedAt = Date.now();
    await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`, { method: 'PATCH', body: patch });
    await audit(req, 'student.update', { studentId: id, patch });
    res.json({ success: true, id, updated: true, patch });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'STUDENT_UPDATE_FAILED', 'Unable to update student.');
  }
});

app.delete('/api/admin/students/:id', requireAdmin, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const current = await getStudent(id);
    if (!current) return fail(res, 404, 'STUDENT_NOT_FOUND', 'Student not found.');
    await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`, {
      method: 'PATCH',
      body: { status: 'deleted', deletedAt: Date.now(), updatedAt: Date.now() }
    });
    await audit(req, 'student.delete', { studentId: id });
    await incrStat('students_deleted_total', 1);
    res.json({ success: true, id, deleted: true });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'STUDENT_DELETE_FAILED', 'Unable to delete student.');
  }
});

app.post('/api/admin/students/:id/change-code', requireAdmin, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const current = await getStudent(id);
    if (!current) return fail(res, 404, 'STUDENT_NOT_FOUND', 'Student not found.');
    if (current.status === 'deleted') return fail(res, 400, 'STUDENT_DELETED', 'Cannot change code for deleted student.');

    let code = '', lookup = '', existing = null;
    for (let attempt = 0; attempt < 25; attempt++) {
      code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
      lookup = codeLookup(code);
      existing = await getStudentByLookup(lookup);
      if (!existing || existing.id === id || existing.data?.status === 'deleted') break;
    }
    if (existing && existing.id !== id && existing.data?.status !== 'deleted')
      return fail(res, 503, 'CODE_GENERATION_FAILED', 'Unable to generate a unique code. Try again.');

    const codeHash = await hashSecret(code);
    await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`, {
      method: 'PATCH',
      body: { codeHash, codeLookup: lookup, codeChangedAt: Date.now(), updatedAt: Date.now() }
    });
    await audit(req, 'student.change-code', { studentId: id });
    res.json({ success: true, id, code });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'CODE_CHANGE_FAILED', 'Unable to change student code.');
  }
});

// ---------------- Admin: student devices ----------------
app.get('/api/admin/students/:id/devices', requireAdmin, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const student = await getStudent(id);
    if (!student) return fail(res, 404, 'STUDENT_NOT_FOUND', 'Student not found.');
    const devices = student.devices || {};
    const list = Object.values(devices).map(d => ({
      deviceId: d.deviceId, name: d.name, status: d.status,
      firstSeenAt: d.firstSeenAt, lastSeenAt: d.lastSeenAt, lastIp: d.lastIp || null
    }));
    res.json({
      success: true, studentId: id,
      maxDevices: Number(student.maxDevices || MAX_DEVICES_DEFAULT),
      activeCount: list.filter(d => d.status === 'active').length,
      count: list.length, devices: list
    });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'DEVICES_READ_FAILED', 'Unable to list devices.');
  }
});

app.delete('/api/admin/students/:id/devices/:deviceId', requireAdmin, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const deviceId = safeId(req.params.deviceId, 'device_id');
    const student = await getStudent(id);
    if (!student) return fail(res, 404, 'STUDENT_NOT_FOUND', 'Student not found.');
    if (!student.devices?.[deviceId]) return fail(res, 404, 'DEVICE_NOT_FOUND', 'Device not found.');
    await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}/devices/${encodeURIComponent(deviceId)}.json`, {
      method: 'PATCH', body: { status: 'removed', removedAt: Date.now(), removedBy: 'admin' }
    });
    await audit(req, 'device.remove', { studentId: id, deviceId });
    res.json({ success: true, studentId: id, deviceId, removed: true });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'DEVICE_REMOVE_FAILED', 'Unable to remove device.');
  }
});

app.post('/api/admin/students/:id/devices/:deviceId/block', requireAdmin, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const deviceId = safeId(req.params.deviceId, 'device_id');
    const reason = String(req.body?.reason || '').slice(0, 200);
    const student = await getStudent(id);
    if (!student) return fail(res, 404, 'STUDENT_NOT_FOUND', 'Student not found.');
    const device = student.devices?.[deviceId];
    if (!device) return fail(res, 404, 'DEVICE_NOT_FOUND', 'Device not found.');
    await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}/devices/${encodeURIComponent(deviceId)}.json`, {
      method: 'PATCH',
      body: { status: 'blocked', blockedAt: Date.now(), blockedBy: 'admin', blockReason: reason }
    });
    await audit(req, 'device.block', { studentId: id, deviceId, reason });
    res.json({ success: true, studentId: id, deviceId, blocked: true });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'DEVICE_BLOCK_FAILED', 'Unable to block device.');
  }
});

app.post('/api/admin/students/:id/devices/:deviceId/unblock', requireAdmin, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const deviceId = safeId(req.params.deviceId, 'device_id');
    const student = await getStudent(id);
    if (!student) return fail(res, 404, 'STUDENT_NOT_FOUND', 'Student not found.');
    const device = student.devices?.[deviceId];
    if (!device) return fail(res, 404, 'DEVICE_NOT_FOUND', 'Device not found.');
    await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}/devices/${encodeURIComponent(deviceId)}.json`, {
      method: 'PATCH',
      body: { status: 'active', unblockedAt: Date.now(), unblockedBy: 'admin', blockReason: null }
    });
    await audit(req, 'device.unblock', { studentId: id, deviceId });
    res.json({ success: true, studentId: id, deviceId, unblocked: true });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'DEVICE_UNBLOCK_FAILED', 'Unable to unblock device.');
  }
});

app.post('/api/admin/students/:id/revoke-tokens', requireAdmin, async (req, res) => {
  try {
    const id = safeId(req.params.id);
    const student = await getStudent(id);
    if (!student) return fail(res, 404, 'STUDENT_NOT_FOUND', 'Student not found.');
    await rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}/${encodeURIComponent(id)}.json`, {
      method: 'PATCH',
      body: { tokenVersion: Date.now(), updatedAt: Date.now() }
    });
    await audit(req, 'student.revoke-tokens', { studentId: id });
    res.json({ success: true, id, revoked: true });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'REVOKE_FAILED', 'Unable to revoke tokens.');
  }
});

// ---------------- Admin: sync video public IDs ----------------
app.post('/api/admin/sync-video-ids', requireAdmin, async (req, res) => {
  if (!needDb(res)) return;
  try {
    const snap = await db.collection('content').get();
    let updated = 0;
    for (const doc of snap.docs) {
      const d = doc.data();
      if ((d.videoUrl || d.url || d.src) && !d.videoPublicId) {
        const pid = publicVideoId(doc.id);
        await db.collection('content').doc(doc.id).update({ videoPublicId: pid });
        updated++;
      }
    }
    await audit(req, 'admin.sync-video-ids', { updated, total: snap.size });
    res.json({ success: true, updated, total: snap.size });
  } catch (e) {
    console.error('[sync-video-ids]', e);
    fail(res, 500, 'SYNC_FAILED', 'Unable to sync video IDs.');
  }
});

// ---------------- Admin: dashboard stats ----------------
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [stats, daily, studentsRaw, bans] = await Promise.all([
      rtdbPath(`${encodeURIComponent(STATS_PATH)}.json`).catch(() => null),
      rtdbPath(`${encodeURIComponent(STATS_PATH)}/daily.json`).catch(() => null),
      rtdbPath(`${encodeURIComponent(STUDENTS_PATH)}.json`).catch(() => null),
      rtdbPath(`${encodeURIComponent(BANS_PATH)}.json`).catch(() => null)
    ]);

    const students = Object.values(studentsRaw || {});
    const active = students.filter(s => s && s.status === 'active' && Number(s.expiresAt || 0) > Date.now()).length;
    const expired = students.filter(s => s && s.status === 'active' && Number(s.expiresAt || 0) <= Date.now()).length;
    const disabled = students.filter(s => s && s.status === 'disabled').length;
    const deleted = students.filter(s => s && s.status === 'deleted').length;
    let totalDevices = 0, activeDevices = 0, blockedDevices = 0;
    for (const s of students) {
      if (!s?.devices) continue;
      for (const d of Object.values(s.devices)) {
        if (!d) continue;
        totalDevices++;
        if (d.status === 'active') activeDevices++;
        else if (d.status === 'blocked') blockedDevices++;
      }
    }

    const bansList = [];
    if (bans && typeof bans === 'object') {
      for (const [scope, map] of Object.entries(bans)) {
        if (!map || typeof map !== 'object') continue;
        for (const [id, info] of Object.entries(map)) {
          bansList.push({ scope, id, ...info });
        }
      }
    }

    const dailyArr = Object.entries(daily || {}).map(([date, v]) => ({ date, ...v }))
      .sort((a, b) => a.date.localeCompare(b.date));

    res.json({
      success: true,
      generatedAt: new Date().toISOString(),
      counters: {
        loginsTotal: Number(stats?.logins_total || 0),
        failedLoginsTotal: Number(stats?.failed_logins_total || 0),
        studentsCreatedTotal: Number(stats?.students_created_total || 0),
        studentsDeletedTotal: Number(stats?.students_deleted_total || 0),
        videoTokensIssued: Number(stats?.video_tokens_issued || 0),
        videoStreamsTotal: Number(stats?.video_streams_total || 0)
      },
      students: {
        total: students.length,
        active, expired, disabled, deleted,
        totalDevices, activeDevices, blockedDevices
      },
      bans: { count: bansList.length, list: bansList.slice(0, 200) },
      daily: dailyArr.slice(-30)
    });
  } catch (e) {
    console.error('[stats]', e);
    fail(res, 500, 'STATS_FAILED', 'Unable to load statistics.');
  }
});

// ---------------- Admin: security overview ----------------
app.get('/api/admin/security/overview', requireAdmin, async (req, res) => {
  try {
    const [bans, attempts, auditRaw] = await Promise.all([
      rtdbPath(`${encodeURIComponent(BANS_PATH)}.json`).catch(() => null),
      rtdbPath(`${encodeURIComponent(ATTEMPTS_PATH)}.json`).catch(() => null),
      rtdbPath(`${encodeURIComponent(AUDIT_PATH)}.json?orderBy=%22at%22&limitToLast=200`).catch(() => null)
    ]);

    const bansList = [];
    if (bans) for (const [scope, map] of Object.entries(bans)) {
      if (!map) continue;
      for (const [id, info] of Object.entries(map)) bansList.push({ scope, id, ...info });
    }

    const attemptsList = attempts
      ? Object.entries(attempts).map(([key, v]) => ({
          key, failedCount: v?.failedCount || 0, total: (v?.attempts || []).length, updatedAt: v?.updatedAt || null
        })).filter(x => x.failedCount > 0)
      : [];

    const auditList = auditRaw ? Object.values(auditRaw).sort((a, b) => (b.at || 0) - (a.at || 0)).slice(0, 200) : [];

    res.json({
      success: true,
      bans: { count: bansList.length, list: bansList.slice(0, 200) },
      attempts: { count: attemptsList.length, list: attemptsList.sort((a, b) => b.failedCount - a.failedCount).slice(0, 200) },
      audit: auditList
    });
  } catch (e) {
    console.error('[security overview]', e);
    fail(res, 500, 'SECURITY_OVERVIEW_FAILED', 'Unable to load security overview.');
  }
});

// ---------------- Admin: unban ----------------
app.delete('/api/admin/bans/:scope/:id', requireAdmin, async (req, res) => {
  try {
    const scope = safeId(req.params.scope, 'scope');
    const id = safeId(req.params.id, 'ban_id');
    if (!['ip', 'device', 'code'].includes(scope))
      return fail(res, 400, 'INVALID_SCOPE', 'Scope must be ip, device, or code.');
    await rtdbPath(`${encodeURIComponent(BANS_PATH)}/${encodeURIComponent(scope)}/${encodeURIComponent(id)}.json`, { method: 'DELETE' });
    await audit(req, 'admin.unban', { scope, id });
    res.json({ success: true, scope, id, unbanned: true });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'UNBAN_FAILED', 'Unable to unban.');
  }
});

// ---------------- 404 + error handler ----------------
app.use((req, res) => fail(res, 404, 'NOT_FOUND', 'Endpoint not found.'));
app.use((err, req, res, next) => {
  console.error('[error]', err);
  if (err?.message === 'CORS_ORIGIN_NOT_ALLOWED')
    return fail(res, 403, 'CORS_BLOCKED', 'Origin is not allowed.');
  return fail(res, 500, 'INTERNAL_ERROR', 'Internal server error.');
});

if (!JWT_SECRET) console.warn('WARNING: API_JWT_SECRET missing.');
if (!ADMIN_USERNAME || !ADMIN_PASSWORD) console.warn('WARNING: ADMIN_USERNAME/ADMIN_PASSWORD missing.');
app.listen(PORT, () => console.log(`Durosak Plus API v5 listening on ${PORT}`));