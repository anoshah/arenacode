const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== قاعدة البيانات (ملف JSON) =====
const DB_PATH = path.join(__dirname, 'users.json');

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ users: {} }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function saveDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'quizarena_salt').digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ===== مسارات API للمصادقة =====

// تسجيل حساب جديد
app.post('/api/register', (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.json({ error: 'جميع الحقول مطلوبة' });
  if (password.length < 6) return res.json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

  const db = loadDB();
  const emailKey = email.toLowerCase().trim();

  if (db.users[emailKey]) return res.json({ error: 'البريد الإلكتروني مسجل مسبقاً' });

  const token = generateToken();
  db.users[emailKey] = {
    name: name.trim(),
    email: emailKey,
    password: hashPassword(password),
    plan: 'free',          // free / pro
    roomsThisMonth: 0,
    monthKey: new Date().toISOString().slice(0, 7), // 2025-03
    createdAt: new Date().toISOString(),
    token
  };

  saveDB(db);
  res.json({ success: true, token, name: db.users[emailKey].name, plan: 'free' });
});

// تسجيل الدخول
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'أدخل البريد وكلمة المرور' });

  const db = loadDB();
  const emailKey = email.toLowerCase().trim();
  const user = db.users[emailKey];

  if (!user) return res.json({ error: 'البريد الإلكتروني غير مسجل' });
  if (user.password !== hashPassword(password)) return res.json({ error: 'كلمة المرور غير صحيحة' });

  // تجديد التوكن
  user.token = generateToken();
  saveDB(db);

  res.json({ success: true, token: user.token, name: user.name, plan: user.plan });
});

// التحقق من التوكن
app.post('/api/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.json({ valid: false });

  const db = loadDB();
  const user = Object.values(db.users).find(u => u.token === token);
  if (!user) return res.json({ valid: false });

  res.json({ valid: true, name: user.name, plan: user.plan });
});

// ===== فحص حصة الغرف =====
function canCreateRoom(token) {
  const db = loadDB();
  const user = Object.values(db.users).find(u => u.token === token);
  if (!user) return { allowed: false, reason: 'يجب تسجيل الدخول أولاً' };

  if (user.plan === 'pro') return { allowed: true, user };

  // مجاني: 3 غرف شهرياً
  const currentMonth = new Date().toISOString().slice(0, 7);
  if (user.monthKey !== currentMonth) {
    user.roomsThisMonth = 0;
    user.monthKey = currentMonth;
  }

  if (user.roomsThisMonth >= 3) {
    return { allowed: false, reason: 'وصلت للحد المجاني (3 غرف/شهر). ترقّ للباقة Pro لغرف غير محدودة!' };
  }

  user.roomsThisMonth++;
  const db2 = loadDB();
  const emailKey = user.email;
  db2.users[emailKey] = user;
  saveDB(db2);

  return { allowed: true, user };
}

// ===== منطق اللعبة =====
const rooms = {};

function generateCode() {
  let code;
  do { code = String(Math.floor(100 + Math.random() * 900)); } while (rooms[code]);
  return code;
}

function getPlayers(room) {
  return Object.values(room.players).sort((a, b) => b.score - a.score);
}

io.on('connection', (socket) => {

  // HOST: إنشاء غرفة (مع فحص الاشتراك)
  socket.on('host:create', ({ name, token }, cb) => {
    const check = canCreateRoom(token);
    if (!check.allowed) return cb({ error: check.reason });

    const code = generateCode();
    rooms[code] = {
      code,
      hostId: socket.id,
      hostName: check.user.name,
      players: {},
      status: 'waiting',
      question: null,
      fastestAnswer: null,
      questionIndex: 0
    };
    rooms[code].players[socket.id] = {
      id: socket.id,
      name,
      score: 0,
      answered: false,
      isHost: true
    };
    socket.join(code);
    socket.roomCode = code;
    socket.isHost = true;
    socket.playerName = name;
    io.to(code).emit('room:players', getPlayers(rooms[code]));
    cb({ code, plan: check.user.plan, roomsLeft: check.user.plan === 'pro' ? '∞' : String(3 - check.user.roomsThisMonth) });
  });

  // GUEST: انضمام
  socket.on('guest:join', ({ code, name }, cb) => {
    const room = rooms[code];
    if (!room) return cb({ error: 'الغرفة غير موجودة!' });
    if (room.status === 'ended') return cb({ error: 'المسابقة انتهت!' });
    const names = Object.values(room.players).map(p => p.name);
    if (names.includes(name)) return cb({ error: 'الاسم مستخدم، اختر اسماً آخر!' });
    room.players[socket.id] = { id: socket.id, name, score: 0, answered: false, isHost: false };
    socket.join(code);
    socket.roomCode = code;
    socket.playerName = name;
    io.to(code).emit('room:players', getPlayers(room));
    cb({ success: true });
  });

  // HOST: بدء
  socket.on('host:start', () => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId) return;
    room.status = 'playing';
    socket.to(socket.roomCode).emit('game:started');
  });

  // HOST: سؤال
  socket.on('host:question', ({ question, options, category, answer, index }) => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId) return;
    Object.keys(room.players).forEach(id => {
      room.players[id].answered = false;
      room.players[id].pendingAnswer = null;
      room.players[id].lastPoints = null;
    });
    room.fastestAnswer = null;
    const now = Date.now();
    room.question = { question, options, category, answer, index, startTime: now };
    room.questionIndex = index;
    io.to(socket.roomCode).emit('question:new', { question, options, category, index, startTime: now, serverNow: now });
    io.to(socket.roomCode).emit('room:players', getPlayers(room));
  });

  // PLAYER: إجابة
  socket.on('player:answer', ({ optIndex }) => {
    const room = rooms[socket.roomCode];
    if (!room || !room.players[socket.id]) return;
    const player = room.players[socket.id];
    if (player.answered) return;
    player.answered = true;
    player.pendingAnswer = optIndex;
    const answerTime = Date.now() - (room.question?.startTime || Date.now());
    const correctAnswer = room.question?.answer;
    const isCorrect = optIndex === correctAnswer;
    if (isCorrect) {
      const elapsedSec = answerTime / 1000;
      const points = Math.max(1, Math.round(10 - elapsedSec));
      player.score += points;
      player.lastPoints = points;
      if (!room.fastestAnswer) {
        room.fastestAnswer = { name: player.name, id: socket.id, time: answerTime };
        io.to(room.hostId).emit('host:fastest', { name: player.name, time: answerTime });
      }
      socket.emit('player:point', { score: player.score, points });
    } else {
      player.lastPoints = 0;
    }
    socket.emit('player:answer:confirm', { isCorrect, optIndex, correctAnswer: isCorrect ? correctAnswer : -1 });
    io.to(socket.roomCode).emit('room:players', getPlayers(room));
  });

  // HOST: كشف الإجابة
  socket.on('host:reveal', () => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId) return;
    const answer = room.question?.answer;
    io.to(socket.roomCode).emit('question:reveal', { correctAnswer: answer });
    io.to(socket.roomCode).emit('room:players', getPlayers(room));
  });

  // HOST: طرد لاعب
  socket.on('host:kick', ({ playerId }, cb) => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId || !room.players[playerId] || playerId === socket.id) return;
    const name = room.players[playerId].name;
    delete room.players[playerId];
    io.to(playerId).emit('player:kicked');
    io.to(socket.roomCode).emit('room:players', getPlayers(room));
    if (cb) cb({ success: true, name });
  });

  // HOST: إنهاء
  socket.on('host:end', () => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId) return;
    room.status = 'ended';
    io.to(socket.roomCode).emit('game:ended', { players: getPlayers(room) });
  });

  // قطع الاتصال
  socket.on('disconnect', () => {
    const code = socket.roomCode;
    if (!code || !rooms[code]) return;
    const room = rooms[code];
    if (socket.isHost) {
      io.to(code).emit('game:host_left');
      delete rooms[code];
    } else if (room.players[socket.id]) {
      delete room.players[socket.id];
      io.to(code).emit('room:players', getPlayers(room));
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 ArenaQuiz on port ${PORT}`));
