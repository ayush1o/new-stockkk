const http = require('node:http');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'fidelity.db');

const db = new DatabaseSync(DB_PATH);
const spinRateLimiter = new Map();
const SPIN_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const SPIN_RATE_LIMIT_MAX_REQUESTS = 10;

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  wallet_balance REAL NOT NULL DEFAULT 0,
  is_admin INTEGER NOT NULL DEFAULT 0,
  last_login_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  stock_name TEXT NOT NULL,
  stock_value REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS stock_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  stock_id INTEGER NOT NULL,
  assigned_by_admin INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK(status IN ('pending','reviewed')) DEFAULT 'pending',
  assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(stock_id) REFERENCES stocks(id)
);

CREATE TABLE IF NOT EXISTS stock_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  stock_id INTEGER NOT NULL,
  rating INTEGER NOT NULL,
  review_text TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(stock_id) REFERENCES stocks(id)
);

CREATE TABLE IF NOT EXISTS spin_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  is_active INTEGER NOT NULL DEFAULT 0,
  start_time TEXT,
  end_time TEXT,
  daily_limit INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS spin_rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reward_name TEXT NOT NULL,
  reward_type TEXT NOT NULL CHECK(reward_type IN ('cash','stock','loss')),
  amount REAL NOT NULL DEFAULT 0,
  probability REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS spin_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  reward_id INTEGER NOT NULL,
  stock_id INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(reward_id) REFERENCES spin_rewards(id),
  FOREIGN KEY(stock_id) REFERENCES stocks(id)
);

CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  message TEXT NOT NULL,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS activity_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS admin_forced_rewards (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  reward_id INTEGER NOT NULL,
  note TEXT,
  is_consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  consumed_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(reward_id) REFERENCES spin_rewards(id)
);
`);

function addColumnIfMissing(table, column, sqlType) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  if (!cols.some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${sqlType}`);
  }
}

addColumnIfMissing('users', 'last_login_at', 'TEXT');
addColumnIfMissing('spin_settings', 'start_time', 'TEXT');
addColumnIfMissing('spin_settings', 'end_time', 'TEXT');
addColumnIfMissing('spin_history', 'stock_id', 'INTEGER');

const settingsCount = db.prepare('SELECT COUNT(*) AS count FROM spin_settings').get().count;
if (!settingsCount) db.prepare('INSERT INTO spin_settings (is_active, start_time, end_time, daily_limit) VALUES (0, NULL, NULL, 1)').run();

const rewardsCount = db.prepare('SELECT COUNT(*) AS count FROM spin_rewards').get().count;
if (!rewardsCount) {
  const rewards = [
    ['Better Luck Next Time', 'loss', 0, 0.4],
    ['₹50 Cash', 'cash', 50, 0.25],
    ['₹100 Cash', 'cash', 100, 0.2],
    ['₹500 Cash', 'cash', 500, 0.1],
    ['₹1000+ Reward', 'stock', 1000, 0.05]
  ];
  const stmt = db.prepare('INSERT INTO spin_rewards (reward_name, reward_type, amount, probability) VALUES (?, ?, ?, ?)');
  for (const reward of rewards) stmt.run(...reward);
}

const stocksCount = db.prepare('SELECT COUNT(*) AS count FROM stocks').get().count;
if (!stocksCount) {
  const stocks = [
    ['Apple', 192.33],
    ['Tesla', 244.9],
    ['Nvidia', 721.4],
    ['Reliance', 2845],
    ['Amazon', 178.2],
    ['HDFC Bank', 1620]
  ];
  const stmt = db.prepare('INSERT INTO stocks (stock_name, stock_value) VALUES (?, ?)');
  for (const stock of stocks) stmt.run(...stock);
}

function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
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
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 })).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyJwt(token) {
  try {
    const [header, body, signature] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (signature !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (payload.exp < Date.now()) return null;
    return payload;
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
  db.prepare('INSERT INTO notifications (user_id, message, is_read) VALUES (?, ?, 0)').run(userId, message);
}

function logActivity(userId, action, metadata = {}) {
  db.prepare('INSERT INTO activity_logs (user_id, action, metadata) VALUES (?, ?, ?)').run(userId, action, JSON.stringify(metadata));
}

function getSpinSettings() {
  return db.prepare('SELECT * FROM spin_settings ORDER BY id DESC LIMIT 1').get();
}

function isSpinWindowOpen(settings) {
  if (!settings?.is_active) return false;
  const now = Date.now();
  if (settings.start_time && now < new Date(settings.start_time).getTime()) return false;
  if (settings.end_time && now > new Date(settings.end_time).getTime()) return false;
  return true;
}

function getRandomStockId() {
  const rows = db.prepare('SELECT id FROM stocks ORDER BY stock_value DESC').all();
  if (!rows.length) return null;
  const top = rows.slice(0, Math.max(1, Math.floor(rows.length * 0.7)));
  return top[Math.floor(Math.random() * top.length)].id;
}

function hasPendingAssignment(userId) {
  return db.prepare("SELECT id FROM stock_assignments WHERE user_id = ? AND status = 'pending' ORDER BY assigned_at DESC LIMIT 1").get(userId);
}

function assignStock(userId, assignedByAdmin = 0, stockId = null) {
  if (hasPendingAssignment(userId)) return null;
  const resolvedStockId = stockId || getRandomStockId();
  if (!resolvedStockId) return null;
  db.prepare('INSERT INTO stock_assignments (user_id, stock_id, assigned_by_admin, status) VALUES (?, ?, ?, ?)').run(userId, resolvedStockId, assignedByAdmin, 'pending');
  const assignment = db.prepare(`SELECT sa.id, sa.user_id, sa.stock_id, sa.status, sa.assigned_at, s.stock_name, s.stock_value
    FROM stock_assignments sa JOIN stocks s ON s.id = sa.stock_id WHERE sa.user_id = ? ORDER BY sa.id DESC LIMIT 1`).get(userId);
  if (assignment) createNotification(userId, `New stock assigned: ${assignment.stock_name} (₹${assignment.stock_value})`);
  return assignment;
}

function pickRewardByProbability() {
  const rewards = db.prepare('SELECT * FROM spin_rewards').all();
  if (!rewards.length) return null;
  const total = rewards.reduce((sum, r) => sum + Number(r.probability), 0);
  if (total <= 0) return null;
  const random = Math.random() * total;
  let running = 0;
  for (const reward of rewards) {
    running += Number(reward.probability);
    if (random <= running) return reward;
  }
  return rewards[rewards.length - 1];
}

function getForcedRewardForUser(userId) {
  return db.prepare(`SELECT afr.id as forced_id, sr.* FROM admin_forced_rewards afr
    JOIN spin_rewards sr ON sr.id = afr.reward_id
    WHERE afr.user_id = ? AND afr.is_consumed = 0 ORDER BY afr.created_at ASC LIMIT 1`).get(userId);
}

function applySpinRateLimit(userId) {
  const now = Date.now();
  const arr = spinRateLimiter.get(userId) || [];
  const recent = arr.filter((ts) => now - ts < SPIN_RATE_LIMIT_WINDOW_MS);
  recent.push(now);
  spinRateLimiter.set(userId, recent);
  return recent.length <= SPIN_RATE_LIMIT_MAX_REQUESTS;
}

function getSpinStatusForUser(userId) {
  const settings = getSpinSettings();
  const spinsUsedToday = db.prepare("SELECT COUNT(*) as count FROM spin_history WHERE user_id = ? AND date(created_at) = date('now')").get(userId).count;
  const dailyLimit = settings?.daily_limit || 1;
  const now = Date.now();
  let reason = 'available';

  if (!settings?.is_active) {
    reason = 'spin_deactivated_by_admin';
  } else if (settings.start_time && now < new Date(settings.start_time).getTime()) {
    reason = 'spin_not_started_yet';
  } else if (settings.end_time && now > new Date(settings.end_time).getTime()) {
    reason = 'spin_window_ended';
  } else if (spinsUsedToday >= dailyLimit) {
    reason = 'daily_limit_reached';
  }

  const canSpin = reason === 'available';
  return {
    is_active: Boolean(settings?.is_active),
    start_time: settings?.start_time || null,
    end_time: settings?.end_time || null,
    daily_limit: dailyLimit,
    spins_used_today: spinsUsedToday,
    can_spin: canSpin,
    reason
  };
}

async function route(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && (url.pathname === '/' || url.pathname.endsWith('.html') || url.pathname.startsWith('/css') || url.pathname.startsWith('/js') || url.pathname.startsWith('/images'))) {
    const filePath = url.pathname === '/' ? path.join(__dirname, 'index.html') : path.join(__dirname, url.pathname.replace(/^\//, ''));
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath);
      const type = ext === '.html' ? 'text/html' : ext === '.css' ? 'text/css' : ext === '.js' ? 'application/javascript' : 'image/png';
      res.writeHead(200, { 'Content-Type': type });
      return res.end(fs.readFileSync(filePath));
    }
  }

  if (req.method === 'POST' && url.pathname === '/auth/signup') {
    const body = await readBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'Invalid JSON body' });
    const { name, email, password } = body;
    if (!name || !email || !password) return json(res, 400, { error: 'name, email and password are required' });
    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(normalizedEmail);
    if (existing) return json(res, 409, { error: 'Email already registered' });

    const info = db.prepare('INSERT INTO users (name, email, password_hash, wallet_balance) VALUES (?, ?, ?, 0)').run(name, normalizedEmail, hashPassword(password));
    const token = signJwt({ userId: info.lastInsertRowid, email: normalizedEmail, isAdmin: false });
    logActivity(info.lastInsertRowid, 'signup', { email: normalizedEmail });
    return json(res, 201, { token, user: { id: info.lastInsertRowid, name, email: normalizedEmail, wallet_balance: 0 } });
  }

  if (req.method === 'POST' && url.pathname === '/auth/login') {
    const body = await readBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'Invalid JSON body' });
    const { email, password } = body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(String(email || '').trim().toLowerCase());
    if (!user || !verifyPassword(password || '', user.password_hash)) return json(res, 401, { error: 'Invalid credentials' });

    const token = signJwt({ userId: user.id, email: user.email, isAdmin: Boolean(user.is_admin) });
    db.prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?').run(user.id);
    logActivity(user.id, 'login', {});
    return json(res, 200, { token, user: { id: user.id, name: user.name, email: user.email, wallet_balance: user.wallet_balance, is_admin: Boolean(user.is_admin) } });
  }

  if (req.method === 'GET' && url.pathname === '/dashboard') {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });

    const user = db.prepare('SELECT id, name, email, wallet_balance FROM users WHERE id = ?').get(auth.userId);
    if (!user) return json(res, 404, { error: 'User not found' });

    let pending = db.prepare(`SELECT sa.id, sa.status, sa.assigned_at, s.id as stock_id, s.stock_name, s.stock_value
      FROM stock_assignments sa JOIN stocks s ON s.id = sa.stock_id
      WHERE sa.user_id = ? AND sa.status = 'pending' ORDER BY sa.assigned_at DESC LIMIT 1`).get(auth.userId);

    if (!pending) pending = assignStock(auth.userId);

    const rewardHistory = db.prepare(`SELECT sh.id, sh.created_at, sr.reward_name, sr.reward_type, sr.amount, sh.stock_id, s.stock_name
      FROM spin_history sh
      JOIN spin_rewards sr ON sr.id = sh.reward_id
      LEFT JOIN stocks s ON s.id = sh.stock_id
      WHERE sh.user_id = ? ORDER BY sh.created_at DESC LIMIT 20`).all(auth.userId);

    const notifications = db.prepare('SELECT id, message, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(auth.userId);

    return json(res, 200, {
      wallet_balance: user.wallet_balance,
      assigned_stock_task: pending,
      review_status: pending ? 'pending' : 'clear',
      spin_status: getSpinStatusForUser(auth.userId),
      reward_history: rewardHistory,
      notifications
    });
  }

  if (req.method === 'GET' && url.pathname === '/spin/status') {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });
    return json(res, 200, getSpinStatusForUser(auth.userId));
  }

  if (req.method === 'POST' && url.pathname === '/spin/play') {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });

    if (!applySpinRateLimit(auth.userId)) {
      logActivity(auth.userId, 'spin_rate_limited', {});
      return json(res, 429, { error: 'Too many spin requests. Please try again shortly.' });
    }

    const status = getSpinStatusForUser(auth.userId);
    if (!status.can_spin) return json(res, 400, { error: 'Spin not available right now', status });

    const forcedReward = getForcedRewardForUser(auth.userId);
    const reward = forcedReward || pickRewardByProbability();
    if (!reward) return json(res, 400, { error: 'No spin reward configured' });

    let stockAssignment = null;
    let stockId = null;

    if (reward.reward_type === 'cash') {
      db.prepare('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?').run(reward.amount, auth.userId);
      createNotification(auth.userId, `You won ${reward.reward_name}. ₹${reward.amount} has been added to your wallet.`);
    } else if (reward.reward_type === 'stock') {
      stockAssignment = assignStock(auth.userId, 0);
      stockId = stockAssignment?.stock_id || null;
      createNotification(auth.userId, `You won ${reward.reward_name}. A high-value stock has been assigned.`);
    } else {
      createNotification(auth.userId, reward.reward_name);
    }

    db.prepare('INSERT INTO spin_history (user_id, reward_id, stock_id) VALUES (?, ?, ?)').run(auth.userId, reward.id, stockId);

    if (forcedReward) {
      db.prepare('UPDATE admin_forced_rewards SET is_consumed = 1, consumed_at = CURRENT_TIMESTAMP WHERE id = ?').run(forcedReward.forced_id);
      logActivity(auth.userId, 'spin_played_forced_reward', { reward_id: reward.id, reward_name: reward.reward_name });
    } else {
      logActivity(auth.userId, 'spin_played_probability_reward', { reward_id: reward.id, reward_name: reward.reward_name });
    }

    return json(res, 200, { reward, stock_assignment: stockAssignment });
  }

  if (req.method === 'POST' && url.pathname === '/review/submit') {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });
    const body = await readBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'Invalid JSON body' });

    const { stock_id, rating, review_text } = body;
    if (Number(rating) !== 5) return json(res, 400, { error: 'Only 5-star reviews are allowed' });

    const pending = db.prepare("SELECT * FROM stock_assignments WHERE user_id = ? AND stock_id = ? AND status = 'pending'").get(auth.userId, stock_id);
    if (!pending) return json(res, 400, { error: 'No pending assignment for this stock' });

    db.prepare('INSERT INTO stock_reviews (user_id, stock_id, rating, review_text) VALUES (?, ?, 5, ?)').run(auth.userId, stock_id, review_text || 'Excellent stock');
    db.prepare("UPDATE stock_assignments SET status = 'reviewed' WHERE id = ?").run(pending.id);

    const nextStock = assignStock(auth.userId);
    logActivity(auth.userId, 'stock_reviewed', { stock_id });
    return json(res, 201, { message: 'Review submitted', next_assignment: nextStock });
  }

  if (req.method === 'GET' && (url.pathname === '/user/reviews' || url.pathname === '/reviews/history')) {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });

    const reviews = db.prepare(`SELECT sr.id, sr.rating, sr.review_text, sr.created_at, s.stock_name, s.stock_value
      FROM stock_reviews sr JOIN stocks s ON s.id = sr.stock_id
      WHERE sr.user_id = ? ORDER BY sr.created_at DESC`).all(auth.userId);
    return json(res, 200, { reviews });
  }

  if (req.method === 'GET' && url.pathname === '/notifications') {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });
    const notifications = db.prepare('SELECT id, message, is_read, created_at FROM notifications WHERE user_id = ? ORDER BY created_at DESC').all(auth.userId);
    return json(res, 200, { notifications });
  }

  if (req.method === 'POST' && url.pathname === '/admin/assign-stock') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });
    const body = await readBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'Invalid JSON body' });

    const { user_id, stock_id } = body;
    const assignment = assignStock(user_id, 1, stock_id);
    if (!assignment) return json(res, 400, { error: 'User has pending stock or stock unavailable' });

    logActivity(auth.userId, 'admin_assign_stock', { user_id, stock_id });
    return json(res, 201, { assignment });
  }

  if (req.method === 'POST' && url.pathname === '/admin/force-reward') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });
    const body = await readBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'Invalid JSON body' });

    const { user_id, reward_id, note } = body;
    const reward = db.prepare('SELECT * FROM spin_rewards WHERE id = ?').get(reward_id);
    if (!reward) return json(res, 404, { error: 'Reward not found' });

    db.prepare('INSERT INTO admin_forced_rewards (user_id, reward_id, note, is_consumed) VALUES (?, ?, ?, 0)').run(user_id, reward_id, note || null);
    createNotification(user_id, `Admin has prepared your next spin reward: ${reward.reward_name}`);
    logActivity(auth.userId, 'admin_force_reward', { user_id, reward_id });
    return json(res, 201, { message: 'Forced reward configured for user' });
  }

  if (req.method === 'POST' && url.pathname === '/admin/spin/activate') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });
    const body = await readBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'Invalid JSON body' });

    const { is_active, daily_limit, start_time, end_time } = body;
    db.prepare('INSERT INTO spin_settings (is_active, start_time, end_time, daily_limit) VALUES (?, ?, ?, ?)')
      .run(is_active ? 1 : 0, start_time || null, end_time || null, Number(daily_limit || 1));

    if (is_active) {
      const users = db.prepare('SELECT id FROM users').all();
      for (const user of users) createNotification(user.id, 'Spin wheel is active. You can spin now!');
    }
    logActivity(auth.userId, 'admin_spin_activate', { is_active, daily_limit, start_time, end_time });
    return json(res, 200, { message: 'Spin settings updated' });
  }

  if (req.method === 'POST' && url.pathname === '/admin/spin/rewards') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });
    const body = await readBody(req).catch(() => null);
    if (!body || !Array.isArray(body.rewards)) return json(res, 400, { error: 'rewards array is required' });

    const validTypes = new Set(['cash', 'stock', 'loss']);
    let totalProbability = 0;
    for (const reward of body.rewards) {
      const probability = Number(reward.probability || 0);
      const amount = Number(reward.amount || 0);
      if (!reward.reward_name || !validTypes.has(reward.reward_type)) {
        return json(res, 400, { error: 'Each reward must have reward_name and valid reward_type (cash/stock/loss)' });
      }
      if (probability < 0 || Number.isNaN(probability)) {
        return json(res, 400, { error: 'Reward probability must be >= 0' });
      }
      if (amount < 0 || Number.isNaN(amount)) {
        return json(res, 400, { error: 'Reward amount must be >= 0' });
      }
      totalProbability += probability;
    }
    if (totalProbability <= 0) {
      return json(res, 400, { error: 'Total probability must be greater than 0' });
    }

    db.exec('BEGIN');
    try {
      db.prepare('DELETE FROM spin_rewards').run();
      const stmt = db.prepare('INSERT INTO spin_rewards (reward_name, reward_type, amount, probability) VALUES (?, ?, ?, ?)');
      for (const reward of body.rewards) {
        stmt.run(reward.reward_name, reward.reward_type, Number(reward.amount || 0), Number(reward.probability || 0));
      }
      db.exec('COMMIT');
      logActivity(auth.userId, 'admin_update_spin_rewards', { count: body.rewards.length });
      return json(res, 200, { message: 'Spin rewards updated' });
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }

  if (req.method === 'GET' && url.pathname === '/admin/spin/logs') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });

    const logs = db.prepare(`SELECT sh.id, sh.created_at, u.email, sr.reward_name, sr.reward_type, sr.amount, s.stock_name
      FROM spin_history sh
      JOIN users u ON u.id = sh.user_id
      JOIN spin_rewards sr ON sr.id = sh.reward_id
      LEFT JOIN stocks s ON s.id = sh.stock_id
      ORDER BY sh.created_at DESC LIMIT 200`).all();
    return json(res, 200, { logs });
  }

  if (req.method === 'GET' && url.pathname === '/admin/dashboard') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });

    const users = db.prepare(`SELECT id, name, email, wallet_balance, is_admin, created_at, last_login_at FROM users ORDER BY created_at DESC`).all();
    const authActivity = db.prepare(`SELECT al.id, al.action, al.created_at, u.id as user_id, u.name, u.email
      FROM activity_logs al LEFT JOIN users u ON u.id = al.user_id
      WHERE al.action IN ('signup', 'login') ORDER BY al.created_at DESC LIMIT 100`).all();

    const stats = {
      total_users: db.prepare('SELECT COUNT(*) as count FROM users').get().count,
      total_reviews: db.prepare('SELECT COUNT(*) as count FROM stock_reviews').get().count,
      total_spins: db.prepare('SELECT COUNT(*) as count FROM spin_history').get().count,
      pending_assignments: db.prepare("SELECT COUNT(*) as count FROM stock_assignments WHERE status = 'pending'").get().count
    };

    return json(res, 200, { stats, users, auth_activity: authActivity });
  }

  if (req.method === 'GET' && url.pathname === '/admin/reviews') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });

    const reviews = db.prepare(`SELECT sr.id, u.email, s.stock_name, sr.rating, sr.review_text, sr.created_at
      FROM stock_reviews sr
      JOIN users u ON u.id = sr.user_id
      JOIN stocks s ON s.id = sr.stock_id
      ORDER BY sr.created_at DESC`).all();
    return json(res, 200, { reviews });
  }

  if (req.method === 'GET' && url.pathname === '/admin/activity-logs') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });

    const logs = db.prepare('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 300').all();
    return json(res, 200, { logs: logs.map((l) => ({ ...l, metadata: l.metadata ? JSON.parse(l.metadata) : null })) });
  }

  return json(res, 404, { error: 'Not Found' });
}

const server = http.createServer((req, res) => {
  route(req, res).catch((error) => {
    json(res, 500, { error: 'Internal server error', detail: error.message });
  });
});

server.listen(PORT, () => {
  console.log(`Fidelity backend listening on http://localhost:${PORT}`);
});
