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
app.use(express.static(path.join(__dirname)));

// ===== مسارات الملفات =====
const DATA_DIR  = path.join(__dirname, 'data');
const USERS_PATH  = path.join(DATA_DIR, 'users.json');
const ADMIN_PATH  = path.join(DATA_DIR, 'admin.json');

// تأكد من وجود مجلد data
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ===== DB helpers =====
function loadUsers() {
  if (!fs.existsSync(USERS_PATH))
    fs.writeFileSync(USERS_PATH, JSON.stringify({ users: {} }, null, 2));
  return JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
}
function saveUsers(data) {
  fs.writeFileSync(USERS_PATH, JSON.stringify(data, null, 2));
}

function loadAdmin() {
  if (!fs.existsSync(ADMIN_PATH)) {
    // كلمة سر افتراضية: admin123  (يجب تغييرها)
    const defaultAdmin = { password: hashPassword('admin123'), sessionTokens: [] };
    fs.writeFileSync(ADMIN_PATH, JSON.stringify(defaultAdmin, null, 2));
  }
  return JSON.parse(fs.readFileSync(ADMIN_PATH, 'utf8'));
}
function saveAdmin(data) {
  fs.writeFileSync(ADMIN_PATH, JSON.stringify(data, null, 2));
}

// ===== Crypto =====
function hashPassword(p) {
  return crypto.createHash('sha256').update(p + 'quizarena_salt').digest('hex');
}
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ===== Middleware: حماية مسارات الأدمن =====
function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  const admin = loadAdmin();
  if (!admin.sessionTokens.includes(token))
    return res.status(401).json({ error: 'الجلسة منتهية، أعد الدخول' });
  next();
}

// ===================================================
// ===== API: المصادقة للمستخدمين (المضيفين) =====
// ===================================================

// تسجيل حساب جديد
app.post('/api/register', (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name)
    return res.json({ error: 'جميع الحقول مطلوبة' });
  if (password.length < 6)
    return res.json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

  const db = loadUsers();
  const key = email.toLowerCase().trim();
  if (db.users[key]) return res.json({ error: 'البريد مسجل مسبقاً' });

  const token = generateToken();
  db.users[key] = {
    name: name.trim(), email: key,
    password: hashPassword(password),
    plan: 'free',
    active: true,
    roomsThisMonth: 0,
    monthKey: new Date().toISOString().slice(0, 7),
    createdAt: new Date().toISOString(),
    token
  };
  saveUsers(db);
  res.json({ success: true, token, name: db.users[key].name, plan: 'free' });
});

// تسجيل الدخول
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ error: 'أدخل البريد وكلمة المرور' });

  const db = loadUsers();
  const key = email.toLowerCase().trim();
  const user = db.users[key];

  if (!user) return res.json({ error: 'البريد غير مسجل' });
  if (!user.active) return res.json({ error: 'الحساب موقوف، تواصل مع الإدارة' });
  if (user.password !== hashPassword(password)) return res.json({ error: 'كلمة المرور غير صحيحة' });

  user.token = generateToken();
  user.lastLogin = new Date().toISOString();
  saveUsers(db);
  res.json({ success: true, token: user.token, name: user.name, plan: user.plan });
});

// التحقق من التوكن
app.post('/api/verify', (req, res) => {
  const { token } = req.body;
  if (!token) return res.json({ valid: false });
  const db = loadUsers();
  const user = Object.values(db.users).find(u => u.token === token);
  if (!user || !user.active) return res.json({ valid: false });
  res.json({ valid: true, name: user.name, plan: user.plan });
});

// ===================================================
// ===== API: لوحة تحكم الأدمن =====
// ===================================================

// دخول الأدمن
app.post('/admin/api/login', (req, res) => {
  const { password } = req.body;
  if (!password) return res.json({ error: 'أدخل كلمة المرور' });

  const admin = loadAdmin();
  if (admin.password !== hashPassword(password))
    return res.json({ error: 'كلمة المرور غير صحيحة' });

  const token = generateToken();
  admin.sessionTokens.push(token);
  // احتفظ بآخر 10 جلسات فقط
  if (admin.sessionTokens.length > 10) admin.sessionTokens.shift();
  saveAdmin(admin);

  res.json({ success: true, token });
});

// تغيير كلمة سر الأدمن
app.post('/admin/api/change-password', adminAuth, (req, res) => {
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6)
    return res.json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

  const admin = loadAdmin();
  admin.password = hashPassword(newPassword);
  admin.sessionTokens = []; // إلغاء جميع الجلسات
  saveAdmin(admin);
  res.json({ success: true });
});

// جلب كل المستخدمين
app.get('/admin/api/users', adminAuth, (req, res) => {
  const db = loadUsers();
  const users = Object.values(db.users).map(u => ({
    email: u.email,
    name: u.name,
    plan: u.plan,
    active: u.active,
    roomsThisMonth: u.roomsThisMonth || 0,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin || null
  }));
  // ترتيب: الأحدث أولاً
  users.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ users });
});

// إضافة مستخدم
app.post('/admin/api/users', adminAuth, (req, res) => {
  const { email, password, name, plan } = req.body;
  if (!email || !password || !name)
    return res.json({ error: 'الاسم والبريد وكلمة المرور مطلوبة' });

  const db = loadUsers();
  const key = email.toLowerCase().trim();
  if (db.users[key]) return res.json({ error: 'البريد مسجل مسبقاً' });

  db.users[key] = {
    name: name.trim(), email: key,
    password: hashPassword(password),
    plan: plan || 'free',
    active: true,
    roomsThisMonth: 0,
    monthKey: new Date().toISOString().slice(0, 7),
    createdAt: new Date().toISOString(),
    token: generateToken()
  };
  saveUsers(db);
  res.json({ success: true });
});

// تعديل مستخدم (اسم / باقة / تفعيل / كلمة مرور)
app.put('/admin/api/users/:email', adminAuth, (req, res) => {
  const db = loadUsers();
  const key = req.params.email.toLowerCase();
  const user = db.users[key];
  if (!user) return res.json({ error: 'المستخدم غير موجود' });

  const { name, plan, active, password, resetRooms } = req.body;
  if (name !== undefined)   user.name = name.trim();
  if (plan !== undefined)   user.plan = plan;
  if (active !== undefined) user.active = active;
  if (password && password.length >= 6) user.password = hashPassword(password);
  if (resetRooms) { user.roomsThisMonth = 0; user.monthKey = new Date().toISOString().slice(0, 7); }

  saveUsers(db);
  res.json({ success: true });
});

// حذف مستخدم
app.delete('/admin/api/users/:email', adminAuth, (req, res) => {
  const db = loadUsers();
  const key = req.params.email.toLowerCase();
  if (!db.users[key]) return res.json({ error: 'المستخدم غير موجود' });
  delete db.users[key];
  saveUsers(db);
  res.json({ success: true });
});

// إحصائيات سريعة
app.get('/admin/api/stats', adminAuth, (req, res) => {
  const db = loadUsers();
  const all = Object.values(db.users);
  res.json({
    total: all.length,
    pro: all.filter(u => u.plan === 'pro').length,
    free: all.filter(u => u.plan === 'free').length,
    active: all.filter(u => u.active).length,
    inactive: all.filter(u => !u.active).length,
  });
});

// ===================================================
// ===== فحص حصة الغرف =====
// ===================================================
function canCreateRoom(token) {
  const db = loadUsers();
  const user = Object.values(db.users).find(u => u.token === token);
  if (!user)         return { allowed: false, reason: 'يجب تسجيل الدخول أولاً' };
  if (!user.active)  return { allowed: false, reason: 'الحساب موقوف، تواصل مع الإدارة' };
  if (user.plan === 'pro') return { allowed: true, user };

  const currentMonth = new Date().toISOString().slice(0, 7);
  if (user.monthKey !== currentMonth) { user.roomsThisMonth = 0; user.monthKey = currentMonth; }

  if (user.roomsThisMonth >= 3)
    return { allowed: false, reason: 'وصلت للحد المجاني (3 غرف/شهر). ترقّ للباقة Pro!' };

  user.roomsThisMonth++;
  const db2 = loadUsers();
  db2.users[user.email] = user;
  saveUsers(db2);
  return { allowed: true, user };
}

// ===================================================
// ===== منطق اللعبة =====
// ===================================================
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

  socket.on('host:create', ({ name, token }, cb) => {
    const check = canCreateRoom(token);
    if (!check.allowed) return cb({ error: check.reason });
    const code = generateCode();
    rooms[code] = { code, hostId: socket.id, hostName: check.user.name, players: {}, status: 'waiting', question: null, fastestAnswer: null, questionIndex: 0 };
    rooms[code].players[socket.id] = { id: socket.id, name, score: 0, answered: false, isHost: true };
    socket.join(code); socket.roomCode = code; socket.isHost = true; socket.playerName = name;
    io.to(code).emit('room:players', getPlayers(rooms[code]));
    cb({ code, plan: check.user.plan, roomsLeft: check.user.plan === 'pro' ? '∞' : String(3 - check.user.roomsThisMonth) });
  });

  socket.on('guest:join', ({ code, name }, cb) => {
    const room = rooms[code];
    if (!room) return cb({ error: 'الغرفة غير موجودة!' });
    if (room.status === 'ended') return cb({ error: 'المسابقة انتهت!' });
    const names = Object.values(room.players).map(p => p.name);
    if (names.includes(name)) return cb({ error: 'الاسم مستخدم، اختر اسماً آخر!' });
    room.players[socket.id] = { id: socket.id, name, score: 0, answered: false, isHost: false };
    socket.join(code); socket.roomCode = code; socket.playerName = name;
    io.to(code).emit('room:players', getPlayers(room));
    cb({ success: true });
  });

  socket.on('host:start', () => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId) return;
    room.status = 'playing';
    socket.to(socket.roomCode).emit('game:started');
  });

  socket.on('host:question', ({ question, options, category, answer, index }) => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId) return;
    Object.keys(room.players).forEach(id => { room.players[id].answered = false; room.players[id].pendingAnswer = null; room.players[id].lastPoints = null; });
    room.fastestAnswer = null;
    const now = Date.now();
    room.question = { question, options, category, answer, index, startTime: now };
    room.questionIndex = index;
    io.to(socket.roomCode).emit('question:new', { question, options, category, index, startTime: now, serverNow: now });
    io.to(socket.roomCode).emit('room:players', getPlayers(room));
  });

  socket.on('player:answer', ({ optIndex }) => {
    const room = rooms[socket.roomCode];
    if (!room || !room.players[socket.id]) return;
    const player = room.players[socket.id];
    if (player.answered) return;
    player.answered = true;
    const answerTime = Date.now() - (room.question?.startTime || Date.now());
    const isCorrect = optIndex === room.question?.answer;
    if (isCorrect) {
      const points = Math.max(1, Math.round(10 - answerTime / 1000));
      player.score += points; player.lastPoints = points;
      if (!room.fastestAnswer) { room.fastestAnswer = { name: player.name, id: socket.id, time: answerTime }; io.to(room.hostId).emit('host:fastest', { name: player.name, time: answerTime }); }
      socket.emit('player:point', { score: player.score, points });
    } else { player.lastPoints = 0; }
    socket.emit('player:answer:confirm', { isCorrect, optIndex, correctAnswer: isCorrect ? room.question.answer : -1 });
    io.to(socket.roomCode).emit('room:players', getPlayers(room));
  });

  socket.on('host:reveal', () => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId) return;
    io.to(socket.roomCode).emit('question:reveal', { correctAnswer: room.question?.answer });
    io.to(socket.roomCode).emit('room:players', getPlayers(room));
  });

  socket.on('host:kick', ({ playerId }, cb) => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId || !room.players[playerId] || playerId === socket.id) return;
    const name = room.players[playerId].name;
    delete room.players[playerId];
    io.to(playerId).emit('player:kicked');
    io.to(socket.roomCode).emit('room:players', getPlayers(room));
    if (cb) cb({ success: true, name });
  });

  socket.on('host:end', () => {
    const room = rooms[socket.roomCode];
    if (!room || socket.id !== room.hostId) return;
    room.status = 'ended';
    io.to(socket.roomCode).emit('game:ended', { players: getPlayers(room) });
  });

  socket.on('disconnect', () => {
    const code = socket.roomCode;
    if (!code || !rooms[code]) return;
    const room = rooms[code];
    if (socket.isHost) { io.to(code).emit('game:host_left'); delete rooms[code]; }
    else if (room.players[socket.id]) { delete room.players[socket.id]; io.to(code).emit('room:players', getPlayers(room)); }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 ArenaQuiz on port ${PORT}`));
