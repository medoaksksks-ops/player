const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const FIREBASE_URL =
  process.env.FIREBASE_DATABASE_URL ||
  "https://english-73376-default-rtdb.firebaseio.com";

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be set and be at least 32 characters.");
  process.exit(1);
}

if (!ADMIN_PASSWORD) {
  console.error("ADMIN_PASSWORD must be set.");
  process.exit(1);
}

const firebaseBase = FIREBASE_URL.replace(/\/+$/, "");

/* =========================
   Firebase helpers
========================= */

async function firebaseRequest(path, options = {}) {
  const url = `${firebaseBase}/${path}.json`;

  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();

  let data = null;

  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    throw new Error(
      `Firebase HTTP ${response.status}: ${
        typeof data === "string" ? data : JSON.stringify(data)
      }`
    );
  }

  return data;
}

function idHash(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function makeDeviceHash(deviceId) {
  return idHash(deviceId);
}

function makeLicenseId(code) {
  return idHash(code);
}

/* =========================
   Code + settings helpers
========================= */

// الكود لازم يكون 9 أرقام بالظبط
function isValidCode(code) {
  return /^\d{9}$/.test(code);
}

function generateCode() {
  return String(crypto.randomInt(100000000, 1000000000));
}

// التوكن العام: واحد لكل الحسابات
async function getGlobalToken() {
  const token = await firebaseRequest("settings/token", {
    method: "GET"
  });

  return typeof token === "string" && token ? token : null;
}

/* =========================
   Firebase database structure
=========================

/settings
{
  token            // التوكن العام اللي بيرجع لكل الحسابات
}

/licenseCodes/{licenseId}
{
  code,            // 9 أرقام
  maxDevices,
  active,
  createdAt,
  devices: {
    {deviceHash}: {
      deviceHash,
      label,
      firstSeen,
      lastSeen,
      active
    }
  }
}

========================= */


/* =========================
   Health
========================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "Coursatk License Server",
    version: "3.1.0",
    database: "Firebase Realtime Database"
  });
});

app.get("/health", async (req, res) => {
  try {
    await firebaseRequest("licenseCodes", {
      method: "GET"
    });

    res.json({
      success: true,
      database: "ok"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      database: "error",
      error: error.message
    });
  }
});


/* =========================
   PUBLIC AUTH
========================= */

app.post("/api/auth/verify", async (req, res) => {
  try {
    const {
      code: rawCode,
      deviceId,
      deviceLabel
    } = req.body || {};

    const code = String(rawCode || "").trim();

    if (!code || !deviceId) {
      return res.status(400).json({
        success: false,
        message: "code and deviceId are required"
      });
    }

    const licenseId = makeLicenseId(code);

    const [license, globalToken] = await Promise.all([
      firebaseRequest(`licenseCodes/${licenseId}`, {
        method: "GET"
      }),
      getGlobalToken()
    ]);

    if (!license) {
      return res.status(404).json({
        success: false,
        message: "Invalid code"
      });
    }

    if (!license.active) {
      return res.status(403).json({
        success: false,
        message: "This code is disabled"
      });
    }

    if (!globalToken) {
      return res.status(503).json({
        success: false,
        message: "Token is not configured on the server"
      });
    }

    const deviceHash = makeDeviceHash(deviceId);

    const devices = license.devices || {};

    let device = devices[deviceHash];

    if (!device) {
      const deviceCount = Object.values(devices).filter(
        d => d && d.active !== false
      ).length;

      const maxDevices = Number(license.maxDevices || 1);

      if (deviceCount >= maxDevices) {
        return res.status(403).json({
          success: false,
          message: "Maximum devices reached",
          maxDevices
        });
      }

      const now = new Date().toISOString();

      device = {
        deviceHash,
        label: deviceLabel || "Unknown device",
        firstSeen: now,
        lastSeen: now,
        active: true
      };

      await firebaseRequest(
        `licenseCodes/${licenseId}/devices/${deviceHash}`,
        {
          method: "PUT",
          body: JSON.stringify(device)
        }
      );
    } else {
      if (device.active === false) {
        return res.status(403).json({
          success: false,
          message: "This device has been disabled"
        });
      }

      await firebaseRequest(
        `licenseCodes/${licenseId}/devices/${deviceHash}/lastSeen`,
        {
          method: "PUT",
          body: JSON.stringify(new Date().toISOString())
        }
      );
    }

    const sessionToken = jwt.sign(
      {
        licenseId,
        deviceHash
      },
      JWT_SECRET,
      {
        expiresIn: "7d"
      }
    );

    res.json({
      success: true,

      // التوكن العام من الإعدادات
      token: globalToken,

      sessionToken,

      redirect: "https://coursatk.online/years"
    });

  } catch (error) {
    console.error("VERIFY ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message
    });
  }
});


/* =========================
   VALIDATE SESSION
========================= */

app.post("/api/auth/validate", async (req, res) => {
  try {
    const { sessionToken } = req.body || {};

    if (!sessionToken) {
      return res.status(400).json({
        success: false,
        message: "sessionToken is required"
      });
    }

    let decoded;

    try {
      decoded = jwt.verify(sessionToken, JWT_SECRET);
    } catch {
      return res.status(401).json({
        success: false,
        valid: false,
        message: "Invalid or expired session"
      });
    }

    const license = await firebaseRequest(
      `licenseCodes/${decoded.licenseId}`,
      {
        method: "GET"
      }
    );

    if (!license || license.active === false) {
      return res.status(401).json({
        success: false,
        valid: false,
        message: "License disabled or deleted"
      });
    }

    const device =
      license.devices &&
      license.devices[decoded.deviceHash];

    if (!device || device.active === false) {
      return res.status(401).json({
        success: false,
        valid: false,
        message: "Device disabled"
      });
    }

    await firebaseRequest(
      `licenseCodes/${decoded.licenseId}/devices/${decoded.deviceHash}/lastSeen`,
      {
        method: "PUT",
        body: JSON.stringify(new Date().toISOString())
      }
    );

    res.json({
      success: true,
      valid: true
    });

  } catch (error) {
    console.error("VALIDATE ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});


/* =========================
   ADMIN LOGIN
========================= */

app.post("/api/admin/login", (req, res) => {
  const { password } = req.body || {};

  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({
      success: false,
      message: "Invalid admin password"
    });
  }

  const token = jwt.sign(
    {
      admin: true
    },
    JWT_SECRET,
    {
      expiresIn: "12h"
    }
  );

  res.json({
    success: true,
    token
  });
});


/* =========================
   ADMIN AUTH MIDDLEWARE
========================= */

function adminAuth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Admin authentication required"
    });
  }

  const token = header.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (!decoded.admin) {
      throw new Error("Not admin");
    }

    req.admin = decoded;

    next();

  } catch {
    return res.status(401).json({
      success: false,
      message: "Invalid admin token"
    });
  }
}


/* =========================
   ADMIN SETTINGS (التوكن العام)
========================= */

app.get("/api/admin/settings", adminAuth, async (req, res) => {
  try {
    const token = await getGlobalToken();

    res.json({
      success: true,
      settings: {
        token: token || ""
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

app.put("/api/admin/settings", adminAuth, async (req, res) => {
  try {
    const token = String((req.body || {}).token || "").trim();

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "token is required"
      });
    }

    if (token.length > 4096) {
      return res.status(400).json({
        success: false,
        message: "token is too long"
      });
    }

    await firebaseRequest("settings/token", {
      method: "PUT",
      body: JSON.stringify(token)
    });

    res.json({
      success: true
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});


/* =========================
   ADMIN STATS
========================= */

app.get("/api/admin/stats", adminAuth, async (req, res) => {
  try {
    const data = await firebaseRequest("licenseCodes", {
      method: "GET"
    });

    const licenses = data
      ? Object.entries(data).map(([id, value]) => ({
          id,
          ...value
        }))
      : [];

    let totalDevices = 0;

    for (const license of licenses) {
      totalDevices += Object.keys(
        license.devices || {}
      ).length;
    }

    res.json({
      success: true,
      stats: {
        codes: licenses.length,
        activeCodes: licenses.filter(x => x.active !== false).length,
        devices: totalDevices
      }
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});


/* =========================
   LIST CODES
========================= */

app.get("/api/admin/codes", adminAuth, async (req, res) => {
  try {
    const data = await firebaseRequest("licenseCodes", {
      method: "GET"
    });

    const codes = data
      ? Object.entries(data).map(([id, value]) => {
          const devices = value.devices || {};

          return {
            id,
            code: value.code,
            maxDevices: value.maxDevices,
            active: value.active !== false,
            createdAt: value.createdAt,
            deviceCount: Object.values(devices).filter(
              d => d && d.active !== false
            ).length
          };
        })
      : [];

    res.json({
      success: true,
      codes
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});


/* =========================
   CREATE CODE
========================= */

app.post("/api/admin/codes", adminAuth, async (req, res) => {
  try {
    const { maxDevices } = req.body || {};

    let code = String((req.body || {}).code || "").trim();

    const max = Number(maxDevices || 1);

    if (!Number.isInteger(max) || max < 1) {
      return res.status(400).json({
        success: false,
        message: "maxDevices must be a positive integer"
      });
    }

    // لو الكود مش مبعوت، السيرفر يولّد كود 9 أرقام
    if (!code) {
      for (let i = 0; i < 10; i++) {
        const candidate = generateCode();

        const taken = await firebaseRequest(
          `licenseCodes/${makeLicenseId(candidate)}`,
          {
            method: "GET"
          }
        );

        if (!taken) {
          code = candidate;
          break;
        }
      }

      if (!code) {
        return res.status(500).json({
          success: false,
          message: "Could not generate a unique code"
        });
      }
    }

    if (!isValidCode(code)) {
      return res.status(400).json({
        success: false,
        message: "code must be exactly 9 digits"
      });
    }

    const licenseId = makeLicenseId(code);

    const existing = await firebaseRequest(
      `licenseCodes/${licenseId}`,
      {
        method: "GET"
      }
    );

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Code already exists"
      });
    }

    const license = {
      code,
      maxDevices: max,
      active: true,
      createdAt: new Date().toISOString(),
      devices: {}
    };

    await firebaseRequest(
      `licenseCodes/${licenseId}`,
      {
        method: "PUT",
        body: JSON.stringify(license)
      }
    );

    res.json({
      success: true,
      id: licenseId,
      code: license
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});


/* =========================
   UPDATE CODE
========================= */

app.patch("/api/admin/codes/:id", adminAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const existing = await firebaseRequest(
      `licenseCodes/${id}`,
      {
        method: "GET"
      }
    );

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: "Code not found"
      });
    }

    const updates = {};

    if (typeof req.body.active === "boolean") {
      updates.active = req.body.active;
    }

    if (req.body.maxDevices !== undefined) {
      const max = Number(req.body.maxDevices);

      if (!Number.isInteger(max) || max < 1) {
        return res.status(400).json({
          success: false,
          message: "Invalid maxDevices"
        });
      }

      updates.maxDevices = max;
    }

    for (const [key, value] of Object.entries(updates)) {
      await firebaseRequest(
        `licenseCodes/${id}/${key}`,
        {
          method: "PUT",
          body: JSON.stringify(value)
        }
      );
    }

    res.json({
      success: true
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});


/* =========================
   DELETE CODE
========================= */

app.delete("/api/admin/codes/:id", adminAuth, async (req, res) => {
  try {
    const id = req.params.id;

    const existing = await firebaseRequest(
      `licenseCodes/${id}`,
      {
        method: "GET"
      }
    );

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: "Code not found"
      });
    }

    await firebaseRequest(
      `licenseCodes/${id}`,
      {
        method: "DELETE"
      }
    );

    res.json({
      success: true,
      message: "Code deleted"
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});


/* =========================
   GET DEVICES
========================= */

app.get(
  "/api/admin/codes/:id/devices",
  adminAuth,
  async (req, res) => {
    try {
      const license = await firebaseRequest(
        `licenseCodes/${req.params.id}`,
        {
          method: "GET"
        }
      );

      if (!license) {
        return res.status(404).json({
          success: false,
          message: "Code not found"
        });
      }

      const devices = Object.entries(
        license.devices || {}
      ).map(([id, device]) => ({
        id,
        ...device
      }));

      res.json({
        success: true,
        devices
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);


/* =========================
   ENABLE / DISABLE DEVICE
========================= */

app.patch(
  "/api/admin/codes/:codeId/devices/:deviceId",
  adminAuth,
  async (req, res) => {
    try {
      const {
        codeId,
        deviceId
      } = req.params;

      if (typeof req.body.active !== "boolean") {
        return res.status(400).json({
          success: false,
          message: "active must be boolean"
        });
      }

      const device = await firebaseRequest(
        `licenseCodes/${codeId}/devices/${deviceId}`,
        {
          method: "GET"
        }
      );

      if (!device) {
        return res.status(404).json({
          success: false,
          message: "Device not found"
        });
      }

      await firebaseRequest(
        `licenseCodes/${codeId}/devices/${deviceId}/active`,
        {
          method: "PUT",
          body: JSON.stringify(req.body.active)
        }
      );

      res.json({
        success: true
      });

    } catch (error) {
      res.status(500).json({
        success: false,
        message: error.message
      });
    }
  }
);


/* =========================
   START SERVER
========================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Firebase: ${firebaseBase}`);
});
