const express = require("express");
const http = require("http");
const cors = require("cors");
const { Server } = require("socket.io");

const app = express();
app.use(cors());
app.get("/", (_req, res) => res.send("Naqal signaling server OK"));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

// code -> { hostId, peerId }
const rooms = new Map();

function genCode() {
  let code;
  do {
    code = String(Math.floor(1000 + Math.random() * 9000)); // 4 digits: 1000-9999
  } while (rooms.has(code));
  return code;
}

io.on("connection", (socket) => {
  socket.on("create-room", (_data, cb) => {
    const code = genCode();
    rooms.set(code, { hostId: socket.id, peerId: null });
    socket.data.code = code;
    socket.data.role = "host";
    cb({ ok: true, code });
  });

  socket.on("join-room", ({ code }, cb) => {
    const room = rooms.get(code);
    if (!room) return cb({ ok: false, error: "الكود غير صحيح" });
    if (room.peerId) return cb({ ok: false, error: "الغرفة مشغولة بالفعل" });
    room.peerId = socket.id;
    socket.data.code = code;
    socket.data.role = "peer";
    cb({ ok: true });
    io.to(room.hostId).emit("peer-joined");
  });

  // Only tiny SDP/ICE handshake messages pass through here — never file bytes.
  socket.on("signal", (msg) => {
    const code = socket.data.code;
    const room = rooms.get(code);
    if (!room) return;
    const targetId = socket.data.role === "host" ? room.peerId : room.hostId;
    if (targetId) io.to(targetId).emit("signal", msg);
  });

  socket.on("disconnect", () => {
    const code = socket.data.code;
    if (!code) return;
    const room = rooms.get(code);
    if (!room) return;
    const otherId = socket.data.role === "host" ? room.peerId : room.hostId;
    if (otherId) io.to(otherId).emit("peer-left");
    if (socket.data.role === "host") rooms.delete(code);
    else room.peerId = null;
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Signaling server running on port " + PORT));
    
