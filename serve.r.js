const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be set and be at least 32 characters.");
  process.exit(1);
}
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 10) {
  console.error("ADMIN_PASSWORD must be set and be at least 10 characters.");
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error("DATABASE_URL must be set.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(cors({
  origin: true,
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "50kb" }));

const ADMIN_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 12);

function randomId(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function adminToken() {
  return jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "12h" });
}

function verifyAdmin(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== "admin") {
      throw new Error("not admin");
    }

    next();
  } catch {
    res.status(401).json({
      success: false,
      message: "غير مصرح"
    });
  }
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_codes (
      id BIGSERIAL PRIMARY KEY,
      code VARCHAR(128) UNIQUE NOT NULL,
      token TEXT NOT NULL,
      max_devices INTEGER NOT NULL DEFAULT 1 CHECK (max_devices > 0),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS devices (
      id BIGSERIAL PRIMARY KEY,
      license_id BIGINT NOT NULL REFERENCES license_codes(id) ON DELETE CASCADE,
      device_hash VARCHAR(64) NOT NULL,
      label VARCHAR(160),
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      UNIQUE(license_id, device_hash)
    );

    CREATE INDEX IF NOT EXISTS idx_devices_license
      ON devices(license_id);

    CREATE INDEX IF NOT EXISTS idx_license_code
      ON license_codes(code);
  `);
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "coursatk-license-server",
    version: "2.0.0"
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ success: true, database: "ok" });
  } catch {
    res.status(503).json({ success: false, database: "error" });
  }
});

/* ---------- Public authentication ---------- */

app.post("/api/auth/verify", async (req, res) => {
  try {
    const code = String(req.body?.code || "").trim();
    const deviceId = String(req.body?.deviceId || "").trim();
    const label = String(req.body?.deviceLabel || "").trim().slice(0, 160);

    if (!code || !deviceId) {
      return res.status(400).json({
        success: false,
        message: "الكود ومعرف الجهاز مطلوبان"
      });
    }

    const result = await pool.query(
      `SELECT * FROM license_codes WHERE code = $1 LIMIT 1`,
      [code]
    );

    if (!result.rows.length || !result.rows[0].active) {
      return res.status(401).json({
        success: false,
        message: "الكود غير صحيح أو متوقف"
      });
    }

    const license = result.rows[0];
    const deviceHash = hash(deviceId);

    const existing = await pool.query(
      `SELECT * FROM devices
       WHERE license_id = $1 AND device_hash = $2
       LIMIT 1`,
      [license.id, deviceHash]
    );

    if (!existing.rows.length) {
      const count = await pool.query(
        `SELECT COUNT(*)::int AS count
         FROM devices
         WHERE license_id = $1 AND active = TRUE`,
        [license.id]
      );

      if (count.rows[0].count >= license.max_devices) {
        return res.status(409).json({
          success: false,
          message: "تم الوصول للحد الأقصى من الأجهزة"
        });
      }

      await pool.query(
        `INSERT INTO devices
         (license_id, device_hash, label)
         VALUES ($1, $2, $3)`,
        [license.id, deviceHash, label || null]
      );
    } else {
      await pool.query(
        `UPDATE devices
         SET last_seen = NOW(), active = TRUE, label = COALESCE($3, label)
         WHERE license_id = $1 AND device_hash = $2`,
        [license.id, deviceHash, label || null]
      );
    }

    const session = jwt.sign(
      {
        type: "license_session",
        licenseId: license.id,
        deviceHash
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token: license.token,
      sessionToken: session,
      redirect: "https://coursatk.online/years"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      success: false,
      message: "خطأ داخلي في السيرفر"
    });
  }
});

app.post("/api/auth/validate", async (req, res) => {
  try {
    const sessionToken = String(req.body?.sessionToken || "");

    if (!sessionToken) {
      return res.status(401).json({
        success: false,
        message: "الجلسة غير موجودة"
      });
    }

    const decoded = jwt.verify(sessionToken, JWT_SECRET);

    const result = await pool.query(
      `SELECT
         l.active AS license_active,
         d.active AS device_active
       FROM license_codes l
       JOIN devices d ON d.license_id = l.id
       WHERE l.id = $1
         AND d.device_hash = $2
       LIMIT 1`,
      [decoded.licenseId, decoded.deviceHash]
    );

    if (
      !result.rows.length ||
      !result.rows[0].license_active ||
      !result.rows[0].device_active
    ) {
      return res.status(401).json({
        success: false,
        valid: false,
        message: "تم تعطيل الكود أو الجهاز"
      });
    }

    await pool.query(
      `UPDATE devices
       SET last_seen = NOW()
       WHERE license_id = $1 AND device_hash = $2`,
      [decoded.licenseId, decoded.deviceHash]
    );

    res.json({ success: true, valid: true });
  } catch {
    res.status(401).json({
      success: false,
      valid: false,
      message: "الجلسة منتهية أو غير صالحة"
    });
  }
});

/* ---------- Admin ---------- */

app.post("/api/admin/login", (req, res) => {
  const password = String(req.body?.password || "");

  if (!bcrypt.compareSync(password, ADMIN_HASH)) {
    return res.status(401).json({
      success: false,
      message: "كلمة مرور الأدمن غير صحيحة"
    });
  }

  res.json({
    success: true,
    token: adminToken()
  });
});

app.get("/api/admin/stats", verifyAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT
      (SELECT COUNT(*) FROM license_codes)::int AS total_codes,
      (SELECT COUNT(*) FROM license_codes WHERE active = TRUE)::int AS active_codes,
      (SELECT COUNT(*) FROM devices)::int AS total_devices,
      (SELECT COUNT(*) FROM devices WHERE active = TRUE)::int AS active_devices
  `);

  res.json({
    success: true,
    stats: result.rows[0]
  });
});

app.get("/api/admin/codes", verifyAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT
      l.id,
      l.code,
      l.max_devices,
      l.active,
      l.created_at,
      COUNT(d.id)::int AS devices_count,
      COUNT(d.id) FILTER (WHERE d.active = TRUE)::int AS active_devices
    FROM license_codes l
    LEFT JOIN devices d ON d.license_id = l.id
    GROUP BY l.id
    ORDER BY l.created_at DESC
  `);

  res.json({
    success: true,
    codes: result.rows
  });
});

app.post("/api/admin/codes", verifyAdmin, async (req, res) => {
  try {
    const code = String(req.body?.code || "").trim();
    const token = String(req.body?.token || "").trim();
    const maxDevices = Number(req.body?.maxDevices);

    if (!code || !token) {
      return res.status(400).json({
        success: false,
        message: "الكود والتوكن مطلوبان"
      });
    }

    if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 1000) {
      return res.status(400).json({
        success: false,
        message: "عدد الأجهزة يجب أن يكون بين 1 و1000"
      });
    }

    const result = await pool.query(
      `INSERT INTO license_codes
       (code, token, max_devices)
       VALUES ($1, $2, $3)
       RETURNING id, code, max_devices, active, created_at`,
      [code, token, maxDevices]
    );

    res.status(201).json({
      success: true,
      code: result.rows[0]
    });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "الكود موجود بالفعل"
      });
    }

    console.error(err);
    res.status(500).json({
      success: false,
      message: "تعذر إنشاء الكود"
    });
  }
});

app.patch("/api/admin/codes/:id", verifyAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id)) {
    return res.status(400).json({ success: false });
  }

  const active =
    typeof req.body?.active === "boolean"
      ? req.body.active
      : null;

  const maxDevices =
    req.body?.maxDevices !== undefined
      ? Number(req.body.maxDevices)
      : null;

  if (active === null && maxDevices === null) {
    return res.status(400).json({
      success: false,
      message: "لا يوجد تعديل"
    });
  }

  if (maxDevices !== null &&
      (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 1000)) {
    return res.status(400).json({
      success: false,
      message: "عدد الأجهزة غير صالح"
    });
  }

  const result = await pool.query(
    `UPDATE license_codes
     SET
       active = COALESCE($1, active),
       max_devices = COALESCE($2, max_devices)
     WHERE id = $3
     RETURNING id, code, max_devices, active`,
    [active, maxDevices, id]
  );

  if (!result.rows.length) {
    return res.status(404).json({
      success: false,
      message: "الكود غير موجود"
    });
  }

  res.json({
    success: true,
    code: result.rows[0]
  });
});

app.delete("/api/admin/codes/:id", verifyAdmin, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id)) {
    return res.status(400).json({ success: false });
  }

  const result = await pool.query(
    `DELETE FROM license_codes
     WHERE id = $1
     RETURNING id`,
    [id]
  );

  if (!result.rows.length) {
    return res.status(404).json({
      success: false,
      message: "الكود غير موجود"
    });
  }

  res.json({
    success: true,
    message: "تم حذف الكود وجميع أجهزته المرتبطة"
  });
});

app.get("/api/admin/codes/:id/devices", verifyAdmin, async (req, res) => {
  const id = Number(req.params.id);

  const result = await pool.query(
    `SELECT
       id,
       label,
       first_seen,
       last_seen,
       active
     FROM devices
     WHERE license_id = $1
     ORDER BY last_seen DESC`,
    [id]
  );

  res.json({
    success: true,
    devices: result.rows
  });
});

app.patch("/api/admin/devices/:id", verifyAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const active =
    typeof req.body?.active === "boolean"
      ? req.body.active
      : null;

  if (!Number.isInteger(id) || active === null) {
    return res.status(400).json({
      success: false,
      message: "بيانات غير صالحة"
    });
  }

  const result = await pool.query(
    `UPDATE devices
     SET active = $1
     WHERE id = $2
     RETURNING id, active`,
    [active, id]
  );

  if (!result.rows.length) {
    return res.status(404).json({
      success: false,
      message: "الجهاز غير موجود"
    });
  }

  res.json({
    success: true,
    device: result.rows[0]
  });
});

initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Coursatk license server running on ${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Database initialization failed:", err);
    process.exit(1);
  });
