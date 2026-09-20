// Durosak Plus API Server - Firestore bridge (OPEN TEST MODE)
// Browser -> Node.js -> Firestore
//
// This server mirrors the Firestore reads currently used by Durosak Plus:
// 1) content where parentId == X
// 2) batch reads for multiple parentIds
// 3) direct document reads
// 4) lecture video-count lookup including "videos" child sections
//
// TEST MODE: routes are intentionally open. Secure them before production.

const express = require('express');
const cors = require('cors');
const path = require('path');
const admin = require('firebase-admin');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// ---------- Firebase ----------
// TEST MODE: this server can use the SAME Firebase Web Config that exists
// inside the Durosak Plus HTML file. Put that config JSON in
// FIREBASE_SERVICE_ACCOUNT_JSON on Railway (the variable name is kept for
// compatibility with the first version of this server).
//
// It also still supports a real Firebase Admin Service Account JSON.

const firebaseApp = require('firebase/app');
const firebaseFirestore = require('firebase/firestore');

let db = null;
let firebaseMode = null;

function initFirestore() {
  if (db) return db;

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!raw) {
    console.warn('Firebase config is not configured.');
    console.warn('Set FIREBASE_SERVICE_ACCOUNT_JSON to the Firebase Web Config JSON.');
    return null;
  }

  let config;
  try {
    config = JSON.parse(raw);
  } catch (_) {
    try {
      config = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
    } catch (error) {
      console.error('Invalid FIREBASE_SERVICE_ACCOUNT_JSON:', error.message);
      return null;
    }
  }

  // The user can paste the exact Web Config from the HTML file.
  if (config && config.apiKey && config.projectId) {
    try {
      const app = firebaseApp.initializeApp(config);
      db = firebaseFirestore.getFirestore(app);
      firebaseMode = 'web-config';
      console.log(`Firebase connected using Web Config: ${config.projectId}`);
      return db;
    } catch (error) {
      console.error('Firebase Web Config initialization failed:', error.message);
      return null;
    }
  }

  // A real Admin Service Account is also accepted for later production use.
  if (config && config.type === 'service_account' && config.private_key && config.client_email) {
    try {
      const admin = require('firebase-admin');
      admin.initializeApp({ credential: admin.credential.cert(config) });
      db = admin.firestore();
      firebaseMode = 'admin-service-account';
      console.log(`Firebase Admin connected: ${config.project_id || 'project'}`);
      return db;
    } catch (error) {
      console.error('Firebase Admin initialization failed:', error.message);
      return null;
    }
  }

  console.error('FIREBASE_SERVICE_ACCOUNT_JSON must contain either the Firebase Web Config or a Service Account JSON.');
  return null;
}

initFirestore();

// Small compatibility wrapper so the rest of this API keeps the same
// Firestore-style calls used by the previous server implementation.
function contentQuery(parentId) {
  if (firebaseMode === 'web-config') {
    const ref = firebaseFirestore.collection(db, 'content');
    return firebaseFirestore.getDocs(
      firebaseFirestore.query(ref, firebaseFirestore.where('parentId', '==', parentId))
    );
  }

  return db.collection('content').where('parentId', '==', parentId).get();
}

function contentDoc(id) {
  if (firebaseMode === 'web-config') {
    return firebaseFirestore.getDoc(firebaseFirestore.doc(db, 'content', id));
  }

  return db.collection('content').doc(id).get();
}

// ---------- Middleware ----------
app.disable('x-powered-by');
app.use(cors({ origin: true, methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] })); // OPEN TEST MODE
app.use(express.json({ limit: '1mb' }));

// ---------- Helpers ----------
function fail(res, status, code, message, extra = {}) {
  return res.status(status).json({
    success: false,
    error: code,
    message,
    ...extra,
  });
}

function needDb(res) {
  if (db) return true;
  fail(
    res,
    503,
    'FIREBASE_NOT_CONFIGURED',
    'Firebase credentials are not configured on the Node.js server.'
  );
  return false;
}

function safeId(value, label = 'id') {
  const v = String(value ?? '').trim();
  if (!v || v.length > 200 || /[\u0000-\u001F]/.test(v)) {
    throw new Error(`INVALID_${label.toUpperCase()}`);
  }
  return v;
}

function parseParentIds(value) {
  const values = Array.isArray(value) ? value : [value];
  const ids = [];

  for (const item of values) {
    if (item === undefined || item === null || item === '') continue;

    // Supports query forms such as:
    // ?parentIds=a,b,c
    // ?parentIds=a&parentIds=b
    const parts = String(item)
      .split(',')
      .map(x => x.trim())
      .filter(Boolean);

    for (const part of parts) {
      ids.push(safeId(part, 'parent_id'));
    }
  }

  return [...new Set(ids)];
}

function serialize(value) {
  if (value === null || value === undefined) return value;

  if (value && typeof value.toDate === 'function' && value.constructor && value.constructor.name === 'Timestamp') {
    return value.toDate().toISOString();
  }

  if (value && typeof value.latitude === 'number' && typeof value.longitude === 'number' && value.constructor && value.constructor.name === 'GeoPoint') {
    return { latitude: value.latitude, longitude: value.longitude };
  }

  if (value && typeof value.path === 'string' && value.constructor && value.constructor.name === 'DocumentReference') {
    return { path: value.path };
  }

  if (Array.isArray(value)) return value.map(serialize);

  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = serialize(item);
    }
    return out;
  }

  return value;
}

function docToItem(doc) {
  return {
    id: doc.id,
    data: serialize(doc.data() || {}),
  };
}

async function readDirectContent(parentId) {
  const snap = await contentQuery(parentId);

  return snap.docs.map(docToItem);
}

// Same nested read pattern used by the current lecture page.
async function readVideoCount(lectureId) {
  const direct = await readDirectContent(lectureId);

  let count = 0;
  const videoSections = [];

  for (const item of direct) {
    const d = item.data || {};
    const type = String(d.type || '').toLowerCase();
    const name = String(d.displayName || d.title || '').trim().toLowerCase();

    if (type === 'video' || type === 'youtube') count++;

    if (
      type === 'section' &&
      (name.includes('فيديو') ||
        name.includes('فديو') ||
        name.includes('video'))
    ) {
      videoSections.push(item.id);
    }
  }

  if (videoSections.length) {
    const children = await Promise.all(
      videoSections.map(sectionId => readDirectContent(sectionId))
    );

    const unique = new Set();
    for (const list of children) {
      for (const item of list) {
        const d = item.data || {};
        const type = String(d.type || '').toLowerCase();
        if (
          (type === 'video' || type === 'youtube') &&
          !unique.has(item.id)
        ) {
          unique.add(item.id);
          count++;
        }
      }
    }
  }

  return {
    lectureId,
    count,
    directItems: direct,
    videoSectionIds: videoSections,
  };
}

// ---------- Basic routes ----------
app.get('/', (req, res) => {
  res.json({
    success: true,
    name: 'Durosak Plus API',
    mode: 'open-development',
    firebaseConfigured: Boolean(db),
    firestoreCollection: 'content',
    message: 'Node.js is running between the website and Firestore.',
  });
});

app.get('/health', (req, res) => {
  res.json({
    success: true,
    firebaseConfigured: Boolean(db),
    time: new Date().toISOString(),
  });
});

// ---------- EXACT Firestore-style content read ----------
// Current website equivalent:
// db.collection("content").where("parentId","==",parentId).get()
//
// Example:
// GET /api/content?parentId=root
// GET /api/content?parentId=LECTURE_ID
app.get('/api/content', async (req, res) => {
  if (!needDb(res)) return;

  try {
    const parentIds = parseParentIds(
      req.query.parentId ?? req.query.parentIds
    );

    if (!parentIds.length) {
      return fail(
        res,
        400,
        'PARENT_ID_REQUIRED',
        'Pass ?parentId=... (or ?parentIds=a,b).'
      );
    }

    const lists = await Promise.all(parentIds.map(readDirectContent));
    const seen = new Set();
    const items = [];

    for (const list of lists) {
      for (const item of list) {
        if (seen.has(item.id)) continue;
        seen.add(item.id);
        items.push(item);
      }
    }

    res.set('Cache-Control', 'no-store');
    return res.json({
      success: true,
      source: 'firestore',
      collection: 'content',
      parentIds,
      count: items.length,
      items,
    });
  } catch (error) {
    console.error('GET /api/content failed:', error);
    return fail(
      res,
      500,
      'FIRESTORE_CONTENT_READ_FAILED',
      error.message
    );
  }
});

// ---------- Direct document read ----------
// GET /api/content/doc/:id
app.get('/api/content/doc/:id', async (req, res) => {
  if (!needDb(res)) return;

  try {
    const id = safeId(req.params.id);
    const snap = await contentDoc(id);

    const exists = typeof snap.exists === 'function' ? snap.exists() : Boolean(snap.exists);
    if (!exists) {
      return fail(res, 404, 'CONTENT_NOT_FOUND', 'Document not found.');
    }

    res.set('Cache-Control', 'no-store');
    return res.json({
      success: true,
      source: 'firestore',
      collection: 'content',
      item: docToItem(snap),
    });
  } catch (error) {
    const status = error.message.startsWith('INVALID_') ? 400 : 500;
    return fail(res, status, 'CONTENT_DOCUMENT_READ_FAILED', error.message);
  }
});

// ---------- Batch children endpoint ----------
// Useful when the frontend has multiple bucket/parent IDs and wants one HTTP request.
// GET /api/content/children?parentIds=A,B,C
app.get('/api/content/children', async (req, res) => {
  if (!needDb(res)) return;

  try {
    const parentIds = parseParentIds(req.query.parentIds ?? req.query.parentId);

    if (!parentIds.length) {
      return fail(
        res,
        400,
        'PARENT_IDS_REQUIRED',
        'Pass ?parentIds=A,B,C.'
      );
    }

    const lists = await Promise.all(parentIds.map(readDirectContent));
    const byParentId = {};
    const items = [];
    const seen = new Set();

    for (let i = 0; i < parentIds.length; i++) {
      byParentId[parentIds[i]] = lists[i];
      for (const item of lists[i]) {
        const key = `${parentIds[i]}:${item.id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        items.push({ parentId: parentIds[i], ...item });
      }
    }

    res.set('Cache-Control', 'no-store');
    return res.json({
      success: true,
      source: 'firestore',
      collection: 'content',
      parentIds,
      count: items.length,
      byParentId,
      items,
    });
  } catch (error) {
    console.error('GET /api/content/children failed:', error);
    return fail(
      res,
      500,
      'FIRESTORE_BATCH_READ_FAILED',
      error.message
    );
  }
});

// ---------- Lecture video count ----------
// Mirrors the current site's extra Firestore calls for lecture cards.
// GET /api/lectures/:lectureId/video-count
app.get('/api/lectures/:lectureId/video-count', async (req, res) => {
  if (!needDb(res)) return;

  try {
    const lectureId = safeId(req.params.lectureId, 'lecture_id');
    const result = await readVideoCount(lectureId);

    res.set('Cache-Control', 'no-store');
    return res.json({
      success: true,
      source: 'firestore',
      ...result,
    });
  } catch (error) {
    console.error('GET /api/lectures/:lectureId/video-count failed:', error);
    return fail(
      res,
      500,
      'LECTURE_VIDEO_COUNT_FAILED',
      error.message
    );
  }
});

// ---------- Optional lecture flattened read ----------
// Mirrors the lecture-page behavior where "فيديوهات المحاضرة" / "ملفات المحاضرة"
// sections are not shown as cards; their children are merged into the lecture list.
// GET /api/lectures/:lectureId/content
app.get('/api/lectures/:lectureId/content', async (req, res) => {
  if (!needDb(res)) return;

  try {
    const lectureId = safeId(req.params.lectureId, 'lecture_id');
    const direct = await readDirectContent(lectureId);

    const bucketSections = direct.filter(item => {
      const d = item.data || {};
      const type = String(d.type || '').toLowerCase();
      const name = String(d.displayName || d.title || '')
        .trim()
        .toLowerCase();

      return (
        type === 'section' &&
        (name.includes('فيديو') ||
          name.includes('فديو') ||
          name.includes('ملف') ||
          name.includes('ملفات') ||
          name.includes('video') ||
          name.includes('file'))
      );
    });

    const bucketIds = bucketSections.map(x => x.id);
    const base = direct.filter(x => !bucketIds.includes(x.id));

    let merged = [...base];

    if (bucketIds.length) {
      const children = await Promise.all(bucketIds.map(readDirectContent));
      const seen = new Set();

      for (const list of children) {
        for (const item of list) {
          if (seen.has(item.id)) continue;
          seen.add(item.id);
          merged.push(item);
        }
      }
    }

    // Current frontend sorts using numeric order after fetching.
    merged.sort((a, b) => {
      const ao = Number(a.data?.order) || 0;
      const bo = Number(b.data?.order) || 0;
      return ao - bo;
    });

    res.set('Cache-Control', 'no-store');
    return res.json({
      success: true,
      source: 'firestore',
      lectureId,
      count: merged.length,
      bucketSectionIds: bucketIds,
      items: merged,
    });
  } catch (error) {
    console.error('GET /api/lectures/:lectureId/content failed:', error);
    return fail(
      res,
      500,
      'LECTURE_CONTENT_READ_FAILED',
      error.message
    );
  }
});

// ---------- Complete tree read ----------
// Reads every descendant under a parent, preserving every Firestore field.
// GET /api/content/tree?parentId=ROOT_ID&maxDepth=20
app.get('/api/content/tree', async (req, res) => {
  if (!needDb(res)) return;
  try {
    const rootId = safeId(req.query.parentId || 'root', 'parent_id');
    const maxDepth = Math.min(Math.max(Number(req.query.maxDepth) || 20, 1), 50);
    const visited = new Set();
    const nodes = [];

    async function walk(parentId, depth) {
      if (depth > maxDepth || visited.has(parentId)) return;
      visited.add(parentId);
      const children = await readDirectContent(parentId);
      for (const item of children) {
        const node = { parentId, depth, ...item };
        nodes.push(node);
        await walk(item.id, depth + 1);
      }
    }

    await walk(rootId, 0);
    res.set('Cache-Control', 'no-store');
    return res.json({ success: true, source: 'firestore', rootParentId: rootId, maxDepth, count: nodes.length, items: nodes });
  } catch (error) {
    console.error('GET /api/content/tree failed:', error);
    return fail(res, 500, 'FIRESTORE_TREE_READ_FAILED', error.message);
  }
});

// ---------- 404 ----------
app.use((req, res) => {
  return fail(res, 404, 'ROUTE_NOT_FOUND', 'Endpoint not found.');
});

// ---------- Error handler ----------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) return next(err);
  return fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Unexpected server error.');
});

app.use((req, res) => {
  return fail(res, 404, 'NOT_FOUND', `Route not found: ${req.method} ${req.path}`);
});

app.use((error, req, res, next) => {
  console.error('Unhandled server error:', error);
  if (res.headersSent) return next(error);
  return fail(res, 500, 'INTERNAL_SERVER_ERROR', 'Unexpected server error.');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Durosak Plus API listening on ${PORT}`);
  console.log(`🔥 Firestore configured: ${Boolean(db)}`);
  console.log('⚠️ OPEN TEST MODE — do not use this configuration for production.');
});
