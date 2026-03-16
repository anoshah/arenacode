const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
const nodemailer = require('nodemailer');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===================================================
// ===== MongoDB =====
// ===================================================
const MONGO_URI = process.env.MONGODB_URI;
if (!MONGO_URI) { console.error('❌ MONGODB_URI غير موجود!'); process.exit(1); }

let usersCol, adminCol, pendingCol;

async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const db = client.db('quizarena');
  usersCol  = db.collection('users');
  adminCol  = db.collection('admin');
  pendingCol = db.collection('pending'); // حسابات بانتظار التفعيل

  await usersCol.createIndex({ email: 1 }, { unique: true });
  await pendingCol.createIndex({ email: 1 }, { unique: true });
  await pendingCol.createIndex({ createdAt: 1 }, { expireAfterSeconds: 86400 }); // تنتهي بعد 24 ساعة

  const adminDoc = await adminCol.findOne({ _id: 'config' });
  if (!adminDoc) {
    await adminCol.insertOne({ _id: 'config', password: hashPassword('admin123'), sessionTokens: [] });
    console.log('✅ تم إنشاء حساب الأدمن الافتراضي (admin123)');
  }
  console.log('✅ MongoDB متصل');
}

// ===================================================
// ===== Nodemailer (Gmail) =====
// ===================================================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS
  }
});

async function sendActivationEmail(toEmail, name, activationLink) {
  await transporter.sendMail({
    from: `"أريناكويز ⚡" <${process.env.GMAIL_USER}>`,
    to: toEmail,
    subject: '✅ تفعيل حسابك في أريناكويز',
    html: `
    <div dir="rtl" style="font-family:Arial,sans-serif;max-width:520px;margin:0 auto;background:#050A1A;color:#E8F4FD;border-radius:16px;overflow:hidden;">
      <div style="background:linear-gradient(135deg,#FFD700,#FFA500);padding:28px;text-align:center;">
        <div style="font-size:48px;">⚡</div>
        <h1 style="margin:8px 0;color:#000;font-size:26px;">أريناكويز</h1>
        <p style="color:#333;margin:0;font-size:13px;">ARENA QUIZ — بطولة المعرفة</p>
      </div>
      <div style="padding:32px;">
        <h2 style="color:#FFD700;margin-bottom:8px;">مرحباً ${name}! 👋</h2>
        <p style="color:#aaa;font-size:15px;line-height:1.7;">شكراً لتسجيلك في أريناكويز. اضغط على الزر أدناه لتفعيل حسابك والبدء في إنشاء المسابقات.</p>
        <div style="text-align:center;margin:32px 0;">
          <a href="${activationLink}" style="background:linear-gradient(135deg,#FFD700,#FFA500);color:#000;text-decoration:none;padding:16px 40px;border-radius:12px;font-size:18px;font-weight:bold;display:inline-block;">
            🚀 تفعيل الحساب
          </a>
        </div>
        <p style="color:#555;font-size:12px;text-align:center;">الرابط صالح لمدة 24 ساعة فقط</p>
        <hr style="border:1px solid #1a2a3a;margin:24px 0;">
        <p style="color:#333;font-size:11px;text-align:center;">إذا لم تقم بإنشاء هذا الحساب، تجاهل هذا الإيميل.</p>
      </div>
    </div>`
  });
}

// ===================================================
// ===== Crypto =====
// ===================================================
function hashPassword(p) {
  return crypto.createHash('sha256').update(p + 'quizarena_salt').digest('hex');
}
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ===================================================
// ===== Admin Middleware =====
// ===================================================
async function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  const adminDoc = await adminCol.findOne({ _id: 'config' });
  if (!adminDoc || !adminDoc.sessionTokens.includes(token))
    return res.status(401).json({ error: 'الجلسة منتهية، أعد الدخول' });
  next();
}

// ===================================================
// ===== API: المستخدمون =====
// ===================================================

// تسجيل — يرسل رابط تفعيل
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.json({ error: 'جميع الحقول مطلوبة' });
    if (password.length < 6) return res.json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

    const key = email.toLowerCase().trim();

    // تحقق إذا البريد مسجل مسبقاً
    const exists = await usersCol.findOne({ email: key });
    if (exists) return res.json({ error: 'البريد مسجل مسبقاً' });

    // احذف أي طلب تسجيل قديم لنفس البريد
    await pendingCol.deleteOne({ email: key });

    // أنشئ رابط التفعيل
    const activationToken = generateToken();
    const BASE_URL = process.env.BASE_URL || `https://${req.headers.host}`;
    const activationLink = `${BASE_URL}/api/activate/${activationToken}`;

    // احفظ في pending مؤقتاً
    await pendingCol.insertOne({
      name: name.trim(), email: key,
      password: hashPassword(password),
      activationToken,
      createdAt: new Date()
    });

    // أرسل الإيميل
    await sendActivationEmail(key, name.trim(), activationLink);

    res.json({ success: true, message: 'تم إرسال رابط التفعيل إلى بريدك الإلكتروني' });
  } catch(e) {
    console.error('Register error:', e.message);
    res.json({ error: 'خطأ في الإرسال، تحقق من بريدك الإلكتروني' });
  }
});

// تفعيل الحساب عبر الرابط
app.get('/api/activate/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const pending = await pendingCol.findOne({ activationToken: token });

    if (!pending) {
      return res.send(`
        <html><head><meta charset="UTF-8"><title>خطأ</title></head>
        <body dir="rtl" style="font-family:Arial;background:#050A1A;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
          <div style="text-align:center;padding:40px;background:rgba(255,51,85,.1);border:1px solid rgba(255,51,85,.3);border-radius:16px;">
            <div style="font-size:56px">❌</div>
            <h2 style="color:#FF3355">رابط غير صالح أو منتهي</h2>
            <p style="color:#aaa">الرابط انتهت صلاحيته أو تم استخدامه مسبقاً</p>
            <a href="/" style="color:#FFD700">← العودة للموقع</a>
          </div>
        </body></html>`);
    }

    // أنشئ الحساب الفعلي
    const userToken = generateToken();
    await usersCol.insertOne({
      name: pending.name, email: pending.email,
      password: pending.password,
      plan: 'free', active: true,
      roomsThisMonth: 0,
      monthKey: new Date().toISOString().slice(0,7),
      createdAt: new Date().toISOString(),
      token: userToken
    });

    // احذف من pending
    await pendingCol.deleteOne({ activationToken: token });

    // أعد توجيه للموقع مع رسالة نجاح
    return res.send(`
      <html><head><meta charset="UTF-8"><title>تم التفعيل</title>
      <meta http-equiv="refresh" content="3;url=/">
      </head>
      <body dir="rtl" style="font-family:Arial;background:#050A1A;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
        <div style="text-align:center;padding:40px;background:rgba(0,255,136,.08);border:1px solid rgba(0,255,136,.3);border-radius:16px;">
          <div style="font-size:56px">🎉</div>
          <h2 style="color:#00FF88">تم تفعيل حسابك بنجاح!</h2>
          <p style="color:#aaa">مرحباً ${pending.name}، يمكنك الآن تسجيل الدخول</p>
          <p style="color:#555;font-size:13px">سيتم تحويلك تلقائياً خلال 3 ثوانٍ...</p>
          <a href="/" style="background:linear-gradient(135deg,#FFD700,#FFA500);color:#000;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:bold;display:inline-block;margin-top:16px;">🚀 ابدأ الآن</a>
        </div>
      </body></html>`);
  } catch(e) {
    console.error('Activate error:', e.message);
    res.send('<h2>خطأ في التفعيل</h2>');
  }
});

// إعادة إرسال رابط التفعيل
app.post('/api/resend-activation', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ error: 'أدخل البريد الإلكتروني' });
    const key = email.toLowerCase().trim();

    const alreadyActive = await usersCol.findOne({ email: key });
    if (alreadyActive) return res.json({ error: 'الحساب مفعّل مسبقاً، سجّل دخولك' });

    const pending = await pendingCol.findOne({ email: key });
    if (!pending) return res.json({ error: 'البريد غير مسجل، أنشئ حساباً جديداً' });

    const activationToken = generateToken();
    const BASE_URL = process.env.BASE_URL || `https://${req.headers.host}`;
    const activationLink = `${BASE_URL}/api/activate/${activationToken}`;

    await pendingCol.updateOne({ email: key }, { $set: { activationToken, createdAt: new Date() } });
    await sendActivationEmail(key, pending.name, activationLink);

    res.json({ success: true, message: 'تم إعادة إرسال رابط التفعيل' });
  } catch(e) {
    res.json({ error: 'خطأ في الإرسال' });
  }
});

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.json({ error: 'أدخل البريد وكلمة المرور' });
    const key = email.toLowerCase().trim();
    const user = await usersCol.findOne({ email: key });

    if (!user) {
      // تحقق إذا في pending
      const pending = await pendingCol.findOne({ email: key });
      if (pending) return res.json({ error: 'الحساب غير مفعّل، تحقق من بريدك الإلكتروني', notActivated: true });
      return res.json({ error: 'البريد غير مسجل' });
    }
    if (!user.active) return res.json({ error: 'الحساب موقوف، تواصل مع الإدارة' });
    if (user.password !== hashPassword(password)) return res.json({ error: 'كلمة المرور غير صحيحة' });

    const token = generateToken();
    await usersCol.updateOne({ email: key }, { $set: { token, lastLogin: new Date().toISOString() } });
    res.json({ success: true, token, name: user.name, plan: user.plan });
  } catch(e) { res.json({ error: 'خطأ في السيرفر' }); }
});

app.post('/api/verify', async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.json({ valid: false });
    const user = await usersCol.findOne({ token });
    if (!user || !user.active) return res.json({ valid: false });
    res.json({ valid: true, name: user.name, plan: user.plan });
  } catch(e) { res.json({ valid: false }); }
});

// ===================================================
// ===== API: الأدمن =====
// ===================================================

app.post('/admin/api/login', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.json({ error: 'أدخل كلمة المرور' });
    const adminDoc = await adminCol.findOne({ _id: 'config' });
    if (adminDoc.password !== hashPassword(password)) return res.json({ error: 'كلمة المرور غير صحيحة' });
    const token = generateToken();
    let tokens = adminDoc.sessionTokens || [];
    tokens.push(token);
    if (tokens.length > 10) tokens = tokens.slice(-10);
    await adminCol.updateOne({ _id: 'config' }, { $set: { sessionTokens: tokens } });
    res.json({ success: true, token });
  } catch(e) { res.json({ error: 'خطأ في السيرفر' }); }
});

app.post('/admin/api/change-password', adminAuth, async (req, res) => {
  try {
    const { newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) return res.json({ error: 'كلمة المرور قصيرة جداً' });
    await adminCol.updateOne({ _id: 'config' }, { $set: { password: hashPassword(newPassword), sessionTokens: [] } });
    res.json({ success: true });
  } catch(e) { res.json({ error: 'خطأ في السيرفر' }); }
});

app.get('/admin/api/users', adminAuth, async (req, res) => {
  try {
    const users = await usersCol.find({}, { projection: { password: 0, token: 0 } }).sort({ createdAt: -1 }).toArray();
    res.json({ users });
  } catch(e) { res.json({ error: 'خطأ في السيرفر' }); }
});

app.post('/admin/api/users', adminAuth, async (req, res) => {
  try {
    const { email, password, name, plan } = req.body;
    if (!email || !password || !name) return res.json({ error: 'الاسم والبريد وكلمة المرور مطلوبة' });
    const key = email.toLowerCase().trim();
    const exists = await usersCol.findOne({ email: key });
    if (exists) return res.json({ error: 'البريد مسجل مسبقاً' });
    await usersCol.insertOne({
      name: name.trim(), email: key, password: hashPassword(password),
      plan: plan || 'free', active: true, roomsThisMonth: 0,
      monthKey: new Date().toISOString().slice(0,7),
      createdAt: new Date().toISOString(), token: generateToken()
    });
    res.json({ success: true });
  } catch(e) { res.json({ error: 'خطأ في السيرفر' }); }
});

app.put('/admin/api/users/:email', adminAuth, async (req, res) => {
  try {
    const key = req.params.email.toLowerCase();
    const { name, plan, active, password, resetRooms } = req.body;
    const updates = {};
    if (name !== undefined)   updates.name   = name.trim();
    if (plan !== undefined)   updates.plan   = plan;
    if (active !== undefined) updates.active = active;
    if (password && password.length >= 6) updates.password = hashPassword(password);
    if (resetRooms) { updates.roomsThisMonth = 0; updates.monthKey = new Date().toISOString().slice(0,7); }
    const result = await usersCol.updateOne({ email: key }, { $set: updates });
    if (result.matchedCount === 0) return res.json({ error: 'المستخدم غير موجود' });
    res.json({ success: true });
  } catch(e) { res.json({ error: 'خطأ في السيرفر' }); }
});

app.delete('/admin/api/users/:email', adminAuth, async (req, res) => {
  try {
    const key = req.params.email.toLowerCase();
    const result = await usersCol.deleteOne({ email: key });
    if (result.deletedCount === 0) return res.json({ error: 'المستخدم غير موجود' });
    res.json({ success: true });
  } catch(e) { res.json({ error: 'خطأ في السيرفر' }); }
});

app.get('/admin/api/stats', adminAuth, async (req, res) => {
  try {
    const [total, pro, free, active, inactive, pending] = await Promise.all([
      usersCol.countDocuments(),
      usersCol.countDocuments({ plan: 'pro' }),
      usersCol.countDocuments({ plan: 'free' }),
      usersCol.countDocuments({ active: true }),
      usersCol.countDocuments({ active: false }),
      pendingCol.countDocuments(),
    ]);
    res.json({ total, pro, free, active, inactive, pending });
  } catch(e) { res.json({ error: 'خطأ في السيرفر' }); }
});

// ===================================================
// ===== فحص حصة الغرف =====
// ===================================================
async function canCreateRoom(token) {
  const user = await usersCol.findOne({ token });
  if (!user)        return { allowed: false, reason: 'يجب تسجيل الدخول أولاً' };
  if (!user.active) return { allowed: false, reason: 'الحساب موقوف، تواصل مع الإدارة' };
  if (user.plan === 'pro') return { allowed: true, user };
  const currentMonth = new Date().toISOString().slice(0,7);
  let roomCount = user.monthKey !== currentMonth ? 0 : (user.roomsThisMonth || 0);
  if (roomCount >= 3) return { allowed: false, reason: 'وصلت للحد المجاني (3 غرف/شهر). ترقّ للباقة Pro!' };
  await usersCol.updateOne({ token }, { $set: { monthKey: currentMonth, roomsThisMonth: roomCount + 1 } });
  const updated = await usersCol.findOne({ token });
  return { allowed: true, user: updated };
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
  socket.on('host:create', async ({ name, token }, cb) => {
    const check = await canCreateRoom(token);
    if (!check.allowed) return cb({ error: check.reason });
    const code = generateCode();
    rooms[code] = { code, hostId: socket.id, players: {}, status: 'waiting', question: null, fastestAnswer: null, questionIndex: 0 };
    rooms[code].players[socket.id] = { id: socket.id, name, score: 0, answered: false, isHost: true };
    socket.join(code); socket.roomCode = code; socket.isHost = true;
    io.to(code).emit('room:players', getPlayers(rooms[code]));
    const roomsLeft = check.user.plan === 'pro' ? '∞' : String(Math.max(0, 3 - (check.user.roomsThisMonth || 0)));
    cb({ code, plan: check.user.plan, roomsLeft });
  });

  socket.on('guest:join', ({ code, name }, cb) => {
    const room = rooms[code];
    if (!room) return cb({ error: 'الغرفة غير موجودة!' });
    if (room.status === 'ended') return cb({ error: 'المسابقة انتهت!' });
    const names = Object.values(room.players).map(p => p.name);
    if (names.includes(name)) return cb({ error: 'الاسم مستخدم، اختر اسماً آخر!' });
    room.players[socket.id] = { id: socket.id, name, score: 0, answered: false, isHost: false };
    socket.join(code); socket.roomCode = code;
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
connectDB().then(() => {
  server.listen(PORT, () => console.log(`🚀 ArenaQuiz on port ${PORT}`));
}).catch(err => {
  console.error('❌ فشل الاتصال بـ MongoDB:', err.message);
  process.exit(1);
});
