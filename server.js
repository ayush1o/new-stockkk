// =============================
// Fidelity Trading Backend
// RESOLVED VERSION (MERGED)
// =============================

const http = require('node:http');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'fidelity.db');

const db = new DatabaseSync(DB_PATH);

/* =============================
   RATE LIMITER (SPIN PROTECTION)
============================= */
const spinRateLimiter = new Map();
const SPIN_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const SPIN_RATE_LIMIT_MAX_REQUESTS = 10;

/* =============================
   DATABASE
============================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  wallet_balance REAL DEFAULT 0,
  is_admin INTEGER DEFAULT 0,
  last_login_at TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stock_name TEXT,
  stock_value REAL
);

CREATE TABLE IF NOT EXISTS stock_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  stock_id INTEGER,
  assigned_by_admin INTEGER DEFAULT 0,
  status TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS stock_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  stock_id INTEGER,
  rating INTEGER,
  review_text TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS spin_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  is_active INTEGER DEFAULT 0,
  start_time TEXT,
  end_time TEXT,
  daily_limit INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS spin_rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reward_name TEXT,
  reward_type TEXT,
  amount REAL,
  probability REAL
);

CREATE TABLE IF NOT EXISTS spin_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  reward_id INTEGER,
  stock_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  message TEXT,
  is_read INTEGER DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT,
  metadata TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_forced_rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  reward_id INTEGER,
  is_consumed INTEGER DEFAULT 0
);
`);

/* =============================
   HELPERS
============================= */

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const key = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${key}`;
}

function verifyPassword(password, stored) {
  const [salt, key] = (stored || '').split(':');
  if (!salt || !key) return false;
  const candidate = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(key, 'hex'));
}

function signJwt(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyJwt(token) {
  try {
    const [h, b, s] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET)
      .update(`${h}.${b}`)
      .digest('base64url');
    if (s !== expected) return null;
    return JSON.parse(Buffer.from(b, 'base64url').toString());
  } catch {
    return null;
  }
}

function authUser(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return null;
  return verifyJwt(auth.replace('Bearer ', ''));
}

function createNotification(userId, message) {
  db.prepare(
    'INSERT INTO notifications (user_id,message) VALUES (?,?)'
  ).run(userId, message);
}

function logActivity(userId, action, meta = {}) {
  db.prepare(
    'INSERT INTO activity_logs (user_id,action,metadata) VALUES (?,?,?)'
  ).run(userId, action, JSON.stringify(meta));
}

/* =============================
   SPIN ENGINE
============================= */

function applySpinRateLimit(userId) {
  const now = Date.now();
  const arr = spinRateLimiter.get(userId) || [];
  const recent = arr.filter(t => now - t < SPIN_RATE_LIMIT_WINDOW_MS);
  recent.push(now);
  spinRateLimiter.set(userId, recent);
  return recent.length <= SPIN_RATE_LIMIT_MAX_REQUESTS;
}

function pickReward() {
  const rewards = db.prepare('SELECT * FROM spin_rewards').all();
  const r = Math.random();
  let running = 0;
  for (const reward of rewards) {
    running += reward.probability;
    if (r <= running) return reward;
  }
  return rewards[rewards.length - 1];
}

/* =============================
   ROUTER
============================= */

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);

  /* ---------- SIGNUP ---------- */
  if (req.method === 'POST' && url.pathname === '/auth/signup') {
    let body = '';
    for await (const chunk of req) body += chunk;
    body = JSON.parse(body);

    const email = body.email.toLowerCase().trim();

    const exists = db.prepare('SELECT id FROM users WHERE email=?').get(email);
    if (exists) return json(res, 409, { error: 'Email exists' });

    const info = db.prepare(
      'INSERT INTO users(name,email,password_hash) VALUES(?,?,?)'
    ).run(body.name, email, hashPassword(body.password));

    const token = signJwt({ userId: info.lastInsertRowid });
    return json(res, 201, { token });
  }

  /* ---------- LOGIN ---------- */
  if (req.method === 'POST' && url.pathname === '/auth/login') {
    let body = '';
    for await (const chunk of req) body += chunk;
    body = JSON.parse(body);

    const user = db.prepare('SELECT * FROM users WHERE email=?')
      .get(body.email.toLowerCase());

    if (!user || !verifyPassword(body.password, user.password_hash))
      return json(res, 401, { error: 'Invalid credentials' });

    const token = signJwt({ userId: user.id, isAdmin: !!user.is_admin });
    logActivity(user.id, 'login');
    return json(res, 200, { token });
  }

  /* ---------- SPIN ---------- */
  if (req.method === 'POST' && url.pathname === '/spin/play') {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });

    if (!applySpinRateLimit(auth.userId))
      return json(res, 429, { error: 'Too many requests' });

    const reward = pickReward();

    if (reward.reward_type === 'cash') {
      db.prepare(
        'UPDATE users SET wallet_balance = wallet_balance + ? WHERE id=?'
      ).run(reward.amount, auth.userId);
    }

    db.prepare(
      'INSERT INTO spin_history(user_id,reward_id) VALUES(?,?)'
    ).run(auth.userId, reward.id);

    createNotification(auth.userId, `You won ${reward.reward_name}`);
    logActivity(auth.userId, 'spin_played', { reward: reward.reward_name });

    return json(res, 200, { reward });
  }

  json(res, 404, { error: 'Not Found' });
}

const server = http.createServer((req, res) =>
  route(req, res).catch(e =>
    json(res, 500, { error: 'Internal error', detail: e.message })
  )
);

server.listen(PORT, () =>
  console.log(`✅ Fidelity backend running http://localhost:${PORT}`)
);

