const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const { WebSocketServer } = require("ws");

const app = express();
const server = http.createServer(app);
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const MAX_APK_MB = Number(process.env.MAX_APK_MB || 700);
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 30 * 60 * 1000);
const RUNNER_TOKEN = process.env.RUNNER_TOKEN || "change-me";
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, "uploads");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(express.json({ limit: "2mb" }));

const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: MAX_APK_MB * 1024 * 1024 }
});

const sessions = new Map();
let runner = null;

function id() {
  return crypto.randomUUID();
}

function send(ws, data) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(data));
}

function broadcast(session, data) {
  for (const ws of session.browsers) send(ws, data);
}

function cleanupSession(sessionId) {
  const s = sessions.get(sessionId);
  if (!s) return;
  for (const ws of s.browsers) {
    try { ws.close(); } catch {}
  }
  try { fs.unlinkSync(s.apkPath); } catch {}
  sessions.delete(sessionId);
}

app.get("/health", (_req, res) => {
  res.json({
    ok: true,
    runnerConnected: !!runner,
    sessions: sessions.size,
    uptime: process.uptime()
  });
});

app.get("/api/runner", (_req, res) => {
  res.json({
    connected: !!runner,
    id: runner?.id || null,
    device: runner?.device || null
  });
});

app.post("/api/sessions", upload.single("apk"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "APK file is required" });
  if (!runner) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(503).json({
      error: "Android runner is not connected",
      hint: "Start runner/runner.js on a machine with ADB and Android."
    });
  }

  const sessionId = id();
  const session = {
    id: sessionId,
    apkPath: req.file.path,
    apkName: req.file.originalname,
    packageName: req.body.packageName || "",
    createdAt: Date.now(),
    browsers: new Set(),
    status: "queued",
    meta: null
  };
  sessions.set(sessionId, session);

  send(runner.ws, {
    type: "install",
    sessionId,
    apkUrl: `/api/sessions/${sessionId}/apk`,
    apkName: session.apkName,
    packageName: session.packageName
  });

  res.json({
    ok: true,
    sessionId,
    status: session.status,
    runner: runner.id
  });
});

app.get("/api/sessions/:id", (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: "Session not found" });
  res.json({
    id: s.id,
    apkName: s.apkName,
    packageName: s.packageName,
    status: s.status,
    createdAt: s.createdAt,
    meta: s.meta
  });
});

app.get("/api/sessions/:id/apk", (req, res) => {
  if (req.get("x-runner-token") !== RUNNER_TOKEN) return res.sendStatus(401);
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).end();
  res.download(s.apkPath, s.apkName);
});

app.delete("/api/sessions/:id", (req, res) => {
  const s = sessions.get(req.params.id);
  if (!s) return res.status(404).json({ error: "Session not found" });
  if (runner) send(runner.ws, { type: "stop", sessionId: s.id });
  cleanupSession(s.id);
  res.json({ ok: true });
});

const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === "/ws") {
    wss.handleUpgrade(req, socket, head, ws => {
      ws._role = "browser";
      ws._sessionId = url.searchParams.get("session");
      wss.emit("connection", ws, req);
    });
  } else if (url.pathname === "/runner") {
    if (url.searchParams.get("token") !== RUNNER_TOKEN) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, ws => {
      ws._role = "runner";
      ws._runnerId = url.searchParams.get("id") || "android-runner";
      wss.emit("connection", ws, req);
    });
  } else {
    socket.destroy();
  }
});

wss.on("connection", (ws) => {
  if (ws._role === "runner") {
    if (runner?.ws) {
      try { runner.ws.close(); } catch {}
    }
    runner = { ws, id: ws._runnerId, device: null };
    console.log("Runner connected:", runner.id);
    send(ws, { type: "server-ready" });

    ws.on("message", (raw, isBinary) => {
      if (isBinary) {
        // Binary frame envelope: 4-byte big-endian JSON header length + JSON + image bytes.
        for (const s of sessions.values()) {
          if (s.runnerSessionId) {
            for (const browser of s.browsers) {
              if (browser.readyState === 1) browser.send(raw, { binary: true });
            }
          }
        }
        return;
      }

      let msg;
      try { msg = JSON.parse(raw.toString()); } catch { return; }

      if (msg.type === "runner-ready") {
        runner.device = msg.device || null;
        for (const s of sessions.values()) broadcast(s, {
          type: "runner",
          connected: true,
          device: runner.device
        });
      } else if (msg.type === "status") {
        const s = sessions.get(msg.sessionId);
        if (!s) return;
        s.status = msg.status || s.status;
        if (msg.packageName) s.packageName = msg.packageName;
        if (msg.meta) s.meta = msg.meta;
        broadcast(s, msg);
      } else if (msg.type === "meta") {
        const s = sessions.get(msg.sessionId);
        if (!s) return;
        s.meta = msg.meta;
        broadcast(s, msg);
      } else if (msg.type === "log") {
        const s = sessions.get(msg.sessionId);
        if (s) broadcast(s, msg);
      }
    });

    ws.on("close", () => {
      if (runner?.ws === ws) {
        runner = null;
        for (const s of sessions.values()) broadcast(s, {
          type: "runner",
          connected: false
        });
      }
    });
    return;
  }

  const s = sessions.get(ws._sessionId);
  if (!s) {
    ws.close();
    return;
  }

  s.browsers.add(ws);
  send(ws, { type: "session", id: s.id, status: s.status, meta: s.meta });

  ws.on("message", raw => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (!runner) return;
    if (msg.type === "input" || msg.type === "launch" || msg.type === "stop") {
      send(runner.ws, { ...msg, sessionId: s.id });
    }
  });

  ws.on("close", () => s.browsers.delete(ws));
});

setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const s of sessions.values()) {
    if (s.createdAt < cutoff) {
      if (runner) send(runner.ws, { type: "stop", sessionId: s.id });
      cleanupSession(s.id);
    }
  }
}, 60_000);


if (process.env.RUNNER_MODE !== "1") {
  server.listen(PORT, HOST, () => {
    console.log(`APK Cloud Runner listening on ${HOST}:${PORT}`);
  });
}


// ================= ANDROID RUNNER MODE =================
// Run this same file with RUNNER_MODE=1 on the Android/ADB machine.
// It connects to the Railway backend and handles APK installation,
// launch, input, and screen frames.
if (process.env.RUNNER_MODE === "1") {
  const os = require("os");
  const { spawn, execFile } = require("child_process");
  const http = require("http");
  const https = require("https");
  const runnerBackend = process.env.BACKEND_URL;
  const runnerToken = process.env.RUNNER_TOKEN;
  const runnerId = process.env.RUNNER_ID || os.hostname();
  const adbBin = process.env.ADB_BIN || "adb";
  const adbSerial = process.env.ADB_SERIAL || "";
  const frameInterval = Number(process.env.FRAME_INTERVAL_MS || 350);
  let runnerSocket, currentSession = null, timer;

  if (!runnerBackend || !runnerToken) {
    console.error("RUNNER_MODE=1 requires BACKEND_URL and RUNNER_TOKEN");
    process.exit(1);
  }

  const adbArgs = a => adbSerial ? ["-s", adbSerial, ...a] : a;
  const adb = args => new Promise((resolve, reject) => {
    execFile(adbBin, adbArgs(args), { maxBuffer: 20 * 1024 * 1024 },
      (err, stdout, stderr) => err ? reject(new Error(stderr || err.message)) : resolve(stdout));
  });
  const adbBuffer = args => new Promise((resolve, reject) => {
    const p = spawn(adbBin, adbArgs(args));
    const chunks = [];
    let err = "";
    p.stdout.on("data", c => chunks.push(c));
    p.stderr.on("data", c => err += c.toString());
    p.on("error", reject);
    p.on("close", code => code === 0 ? resolve(Buffer.concat(chunks)) : reject(new Error(err || `adb exit ${code}`)));
  });
  const downloadFile = (url, out, headers={}) => new Promise((resolve, reject) => {
    const u = new URL(url), lib = u.protocol === "https:" ? https : http;
    const req = lib.get(u, {headers}, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location)
        return downloadFile(new URL(res.headers.location, url).href, out, headers).then(resolve, reject);
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      const f = require("fs").createWriteStream(out);
      res.pipe(f); f.on("finish", () => f.close(resolve)); f.on("error", reject);
    });
    req.on("error", reject);
  });
  const sendRunner = x => { if (runnerSocket?.readyState === 1) runnerSocket.send(JSON.stringify(x)); };
  const meta = async () => {
    const m = (await adb(["shell","wm","size"])).match(/Physical size:\s*(\d+)x(\d+)/i);
    return m ? {width:+m[1], height:+m[2]} : null;
  };

  async function install(m) {
    currentSession = {sessionId:m.sessionId, packageName:m.packageName || ""};
    sendRunner({type:"status",sessionId:m.sessionId,status:"downloading"});
    const tmp = require("path").join(os.tmpdir(), `${m.sessionId}.apk`);
    await downloadFile(new URL(m.apkUrl, runnerBackend).href, tmp, {"x-runner-token":runnerToken});
    sendRunner({type:"status",sessionId:m.sessionId,status:"installing"});
    const before = new Set((await adb(["shell","pm","list","packages"])).split(/\r?\n/).map(x=>x.replace(/^package:/,"").trim()).filter(Boolean));
    const result = await adb(["install","-r",tmp]);
    require("fs").unlink(tmp,()=>{});
    if (!/Success/i.test(result)) throw new Error(result || "adb install failed");
    let pkg = m.packageName || "";
    if (!pkg) {
      const after = (await adb(["shell","pm","list","packages"])).split(/\r?\n/).map(x=>x.replace(/^package:/,"").trim()).filter(Boolean);
      pkg = after.find(x=>!before.has(x)) || "";
    }
    currentSession.packageName = pkg;
    const deviceMeta = await meta();
    sendRunner({type:"meta",sessionId:m.sessionId,meta:deviceMeta});
    sendRunner({type:"status",sessionId:m.sessionId,status:"installed",packageName:pkg,meta:deviceMeta});
    if (pkg) await launch(pkg,m.sessionId);
  }
  async function launch(pkg, sessionId) {
    if (!pkg) throw new Error("Package name is missing.");
    await adb(["shell","monkey","-p",pkg,"1"]);
    sendRunner({type:"status",sessionId,status:"running",packageName:pkg});
  }
  async function input(m) {
    if (!currentSession || currentSession.sessionId !== m.sessionId) return;
    if (m.action==="tap") await adb(["shell","input","tap",String(m.x),String(m.y)]);
    else if (m.action==="swipe") await adb(["shell","input","swipe",String(m.x1),String(m.y1),String(m.x2),String(m.y2),String(m.duration||300)]);
    else if (m.action==="key") await adb(["shell","input","keyevent",String(m.keycode)]);
    else if (m.action==="text") await adb(["shell","input","text",String(m.text||"").replace(/ /g,"%s")]);
  }
  async function frame() {
    if (!currentSession || !runnerSocket || runnerSocket.readyState !== 1) return;
    try {
      const png = await adbBuffer(["exec-out","screencap","-p"]);
      const h = Buffer.from(JSON.stringify({sessionId:currentSession.sessionId,mime:"image/png"}));
      const b = Buffer.allocUnsafe(4+h.length+png.length);
      b.writeUInt32BE(h.length,0); h.copy(b,4); png.copy(b,4+h.length);
      runnerSocket.send(b);
    } catch {}
  }
  function connectRunner() {
    const WebSocket = require("ws");
    const u = new URL(runnerBackend);
    const proto = u.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${u.host}/runner?token=${encodeURIComponent(runnerToken)}&id=${encodeURIComponent(runnerId)}`);
    runnerSocket = ws;
    ws.on("open", async () => {
      let device="unknown"; try { device=(await adb(["shell","getprop","ro.product.model"])).trim(); } catch {}
      sendRunner({type:"runner-ready",device});
      clearInterval(timer); timer=setInterval(frame,frameInterval);
      console.log("Android runner connected:",runnerId);
    });
    ws.on("message", async raw => {
      if (typeof raw !== "string" && !Buffer.isBuffer(raw)) return;
      let m; try { m=JSON.parse(raw.toString()); } catch { return; }
      try {
        if(m.type==="install") await install(m);
        else if(m.type==="input") await input(m);
        else if(m.type==="launch") await launch(currentSession?.packageName,m.sessionId);
        else if(m.type==="stop" && currentSession?.sessionId===m.sessionId) currentSession=null;
      } catch(e) { sendRunner({type:"status",sessionId:m.sessionId,status:"error",log:e.message}); }
    });
    ws.on("close",()=>{ clearInterval(timer); setTimeout(connectRunner,2500); });
    ws.on("error",e=>console.error("Runner WS:",e.message));
  }
  connectRunner();
}
