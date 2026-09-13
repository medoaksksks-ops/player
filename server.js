/**
 * NAQAL — Fast Local/P2P File Transfer Signaling Backend
 * Node.js + Express + Socket.IO
 *
 * IMPORTANT:
 * This server is a SIGNALING server. It does NOT receive, store, or proxy
 * the file bytes. The browser clients transfer files over WebRTC DataChannel.
 *
 * Railway:
 *   npm start
 *
 * Environment:
 *   PORT        Railway supplies this automatically.
 *   ROOM_TTL_MS Optional room lifetime, default 30 minutes.
 *   MAX_ROOMS   Optional safety limit, default 5000.
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const express = require('express');
const { Server } = require('socket.io');

const app = express();
const httpServer = http.createServer(app);

const PORT = Number(process.env.PORT) || 3000;
const ROOM_TTL_MS = Number(process.env.ROOM_TTL_MS) || 30 * 60 * 1000;
const MAX_ROOMS = Number(process.env.MAX_ROOMS) || 5000;

// Socket.IO is used only for tiny signaling messages.
// File data must be sent through WebRTC from the browser.
const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
  transports: ['websocket', 'polling'],
  pingInterval: 25000,
  pingTimeout: 20000,
  maxHttpBufferSize: 1024 * 1024, // signaling only; never file-sized
  perMessageDeflate: false
});

const rooms = new Map();

app.disable('x-powered-by');
app.get('/health', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    ok: true,
    service: 'naqal-signaling',
    rooms: rooms.size,
    uptime: Math.floor(process.uptime())
  });
});

app.get('/', (req, res) => {
  res.type('text').send('Naqal signaling server is running.');
});

function generateCode() {
  // 6 digits, with crypto randomness.
  let code;
  do {
    code = String(crypto.randomInt(100000, 1000000));
  } while (rooms.has(code));
  return code;
}

function destroyRoom(code, notify = true) {
  const room = rooms.get(code);
  if (!room) return;

  if (notify) {
    const other = room.host === room.peer ? null :
      room.host ? (room.peer || null) : null;
    if (other) io.to(other).emit('peer-left');
  }

  rooms.delete(code);
}

function validCode(value) {
  return /^[0-9]{6}$/.test(String(value || ''));
}

io.on('connection', socket => {
  socket.data.room = null;
  socket.data.role = null;

  // HOST: create a six-digit room.
  socket.on('create-room', (payload, ack) => {
    if (rooms.size >= MAX_ROOMS) {
      return ack?.({ ok: false, error: 'الخادم ممتلئ مؤقتًا، حاول بعد قليل.' });
    }

    if (socket.data.room) {
      return ack?.({ ok: false, error: 'هذا الجهاز متصل بالفعل.' });
    }

    const code = generateCode();

    rooms.set(code, {
      host: socket.id,
      peer: null,
      createdAt: Date.now(),
      lastActivity: Date.now()
    });

    socket.data.room = code;
    socket.data.role = 'host';
    socket.join(code);

    ack?.({ ok: true, code, expiresIn: ROOM_TTL_MS });
  });

  // PEER: enter the six-digit code.
  socket.on('join-room', (payload, ack) => {
    if (socket.data.room) {
      return ack?.({ ok: false, error: 'هذا الجهاز متصل بالفعل.' });
    }

    const code = String(payload?.code || '').trim();

    if (!validCode(code)) {
      return ack?.({ ok: false, error: 'الكود يجب أن يكون 6 أرقام.' });
    }

    const room = rooms.get(code);

    if (!room) {
      return ack?.({ ok: false, error: 'الكود غير موجود أو انتهت صلاحيته.' });
    }

    if (room.peer) {
      return ack?.({ ok: false, error: 'هذا الاتصال مستخدم بالفعل.' });
    }

    room.peer = socket.id;
    room.lastActivity = Date.now();

    socket.data.room = code;
    socket.data.role = 'peer';
    socket.join(code);

    ack?.({ ok: true });

    // Tell host that the second device arrived.
    io.to(room.host).emit('peer-joined');
  });

  /*
   * WebRTC signaling:
   * offer / answer / candidate messages are tiny.
   *
   * The backend forwards them to the other browser and immediately forgets
   * them. No file content passes through this handler.
   */
  socket.on('signal', message => {
    const code = socket.data.room;
    const room = rooms.get(code);
    if (!room) return;

    room.lastActivity = Date.now();

    const target =
      socket.id === room.host ? room.peer :
      socket.id === room.peer ? room.host :
      null;

    if (!target) return;

    if (!message || typeof message !== 'object') return;

    io.to(target).emit('signal', {
      type: message.type,
      data: message.data
    });
  });

  socket.on('keep-alive', () => {
    const room = rooms.get(socket.data.room);
    if (room) room.lastActivity = Date.now();
  });

  socket.on('disconnect', () => {
    const code = socket.data.room;
    const room = rooms.get(code);
    if (!room) return;

    const other =
      socket.id === room.host ? room.peer :
      socket.id === room.peer ? room.host :
      null;

    if (other) io.to(other).emit('peer-left');

    rooms.delete(code);
  });
});

// Cleanup abandoned rooms.
setInterval(() => {
  const now = Date.now();

  for (const [code, room] of rooms) {
    if (now - room.lastActivity > ROOM_TTL_MS) {
      rooms.delete(code);
    }
  }
}, 60_000).unref();

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Naqal signaling server listening on port ${PORT}`);
});
