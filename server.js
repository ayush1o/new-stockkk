const http = require('node:http');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'fidelity.db');

const db = new DatabaseSync(DB_PATH);

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
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(reward_id) REFERENCES spin_rewards(id)
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
`);

const userColumns = db.prepare('PRAGMA table_info(users)').all();
if (!userColumns.some((col) => col.name === 'last_login_at')) {
  db.exec('ALTER TABLE users ADD COLUMN last_login_at TEXT');
}

const settingsCount = db.prepare('SELECT COUNT(*) AS count FROM spin_settings').get().count;
if (!settingsCount) db.prepare('INSERT INTO spin_settings (is_active, daily_limit) VALUES (0, 1)').run();

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
  const [salt, key] = stored.split(':');
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

function getRandomStockId() {
  const rows = db.prepare('SELECT id FROM stocks').all();
  return rows[Math.floor(Math.random() * rows.length)]?.id;
}

function hasPendingAssignment(userId) {
  return db.prepare("SELECT id FROM stock_assignments WHERE user_id = ? AND status = 'pending' ORDER BY assigned_at DESC LIMIT 1").get(userId);
}

function assignStock(userId, assignedByAdmin = 0, stockId = null) {
  const existing = hasPendingAssignment(userId);
  if (existing) return null;
  const resolvedStockId = stockId || getRandomStockId();
  if (!resolvedStockId) return null;
  db.prepare('INSERT INTO stock_assignments (user_id, stock_id, assigned_by_admin, status) VALUES (?, ?, ?, ?)').run(userId, resolvedStockId, assignedByAdmin, 'pending');
  return db.prepare(`SELECT sa.id, sa.status, sa.assigned_at, s.stock_name, s.stock_value
                     FROM stock_assignments sa JOIN stocks s ON s.id = sa.stock_id
                     WHERE sa.user_id = ? ORDER BY sa.id DESC LIMIT 1`).get(userId);
}

function createNotification(userId, message) {
  db.prepare('INSERT INTO notifications (user_id, message, is_read) VALUES (?, ?, 0)').run(userId, message);
}

function logActivity(userId, action, metadata = {}) {
  db.prepare('INSERT INTO activity_logs (user_id, action, metadata) VALUES (?, ?, ?)').run(userId, action, JSON.stringify(metadata));
}

function pickReward() {
  const rewards = db.prepare('SELECT * FROM spin_rewards').all();
  const r = Math.random();
  let running = 0;
  for (const reward of rewards) {
    running += Number(reward.probability);
    if (r <= running) return reward;
  }
  return rewards[rewards.length - 1];
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
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (existing) return json(res, 409, { error: 'Email already registered' });

    const info = db.prepare('INSERT INTO users (name, email, password_hash, wallet_balance) VALUES (?, ?, ?, 0)').run(name, email.toLowerCase(), hashPassword(password));
    const token = signJwt({ userId: info.lastInsertRowid, email: email.toLowerCase(), isAdmin: false });
    logActivity(info.lastInsertRowid, 'signup', { email });
    return json(res, 201, { token, user: { id: info.lastInsertRowid, name, email, wallet_balance: 0 } });
  }

  if (req.method === 'POST' && url.pathname === '/auth/login') {
    const body = await readBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'Invalid JSON body' });
    const { email, password } = body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get((email || '').toLowerCase());
    if (!user || !verifyPassword(password || '', user.password_hash)) return json(res, 401, { error: 'Invalid credentials' });
    const token = signJwt({ userId: user.id, email: user.email, isAdmin: Boolean(user.is_admin) });
    db.prepare("UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?").run(user.id);
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

    const spinSetting = db.prepare('SELECT is_active, daily_limit FROM spin_settings ORDER BY id DESC LIMIT 1').get();
    const todaysSpins = db.prepare("SELECT COUNT(*) as count FROM spin_history WHERE user_id = ? AND date(created_at) = date('now')").get(auth.userId).count;

    const rewardHistory = db.prepare(`SELECT sh.created_at, sr.reward_name, sr.reward_type, sr.amount
      FROM spin_history sh JOIN spin_rewards sr ON sr.id = sh.reward_id
      WHERE sh.user_id = ? ORDER BY sh.created_at DESC LIMIT 10`).all(auth.userId);

    return json(res, 200, {
      wallet_balance: user.wallet_balance,
      assigned_stock_task: pending,
      spin_status: {
        is_active: Boolean(spinSetting?.is_active),
        daily_limit: spinSetting?.daily_limit || 1,
        spins_used_today: todaysSpins,
        can_spin: Boolean(spinSetting?.is_active) && todaysSpins < (spinSetting?.daily_limit || 1)
      },
      reward_history: rewardHistory
    });
  }

  if (req.method === 'GET' && url.pathname === '/spin/status') {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });
    const spinSetting = db.prepare('SELECT is_active, daily_limit FROM spin_settings ORDER BY id DESC LIMIT 1').get();
    const todaysSpins = db.prepare("SELECT COUNT(*) as count FROM spin_history WHERE user_id = ? AND date(created_at) = date('now')").get(auth.userId).count;
    return json(res, 200, {
      is_active: Boolean(spinSetting?.is_active),
      daily_limit: spinSetting?.daily_limit || 1,
      spins_used_today: todaysSpins,
      can_spin: Boolean(spinSetting?.is_active) && todaysSpins < (spinSetting?.daily_limit || 1)
    });
  }

  if (req.method === 'POST' && url.pathname === '/spin/play') {
    const auth = authUser(req);
    if (!auth) return json(res, 401, { error: 'Unauthorized' });

    const spinSetting = db.prepare('SELECT is_active, daily_limit FROM spin_settings ORDER BY id DESC LIMIT 1').get();
    if (!spinSetting?.is_active) return json(res, 400, { error: 'Spin wheel is deactivated by admin' });

    const todaysSpins = db.prepare("SELECT COUNT(*) as count FROM spin_history WHERE user_id = ? AND date(created_at) = date('now')").get(auth.userId).count;
    if (todaysSpins >= spinSetting.daily_limit) return json(res, 429, { error: 'Daily spin limit reached' });

    const reward = pickReward();
    db.prepare('INSERT INTO spin_history (user_id, reward_id) VALUES (?, ?)').run(auth.userId, reward.id);

    let stockAssignment = null;
    if (reward.reward_type === 'cash') {
      db.prepare('UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?').run(reward.amount, auth.userId);
    } else if (reward.reward_type === 'stock') {
      stockAssignment = assignStock(auth.userId, 0);
    }

    logActivity(auth.userId, 'spin_played', { reward: reward.reward_name, amount: reward.amount });
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

  if (req.method === 'GET' && url.pathname === '/user/reviews') {
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
    if (!assignment) return json(res, 400, { error: 'User already has pending stock assignment or stock unavailable' });
    createNotification(user_id, `Admin assigned stock: ${assignment.stock_name}`);
    logActivity(auth.userId, 'admin_assign_stock', { user_id, stock_id });
    return json(res, 201, { assignment });
  }

  if (req.method === 'POST' && url.pathname === '/admin/spin/activate') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });
    const body = await readBody(req).catch(() => null);
    if (!body) return json(res, 400, { error: 'Invalid JSON body' });
    const { is_active, daily_limit } = body;
    db.prepare('INSERT INTO spin_settings (is_active, daily_limit) VALUES (?, ?)').run(is_active ? 1 : 0, Number(daily_limit || 1));

    if (is_active) {
      const users = db.prepare('SELECT id FROM users').all();
      for (const user of users) createNotification(user.id, 'Spin wheel has been activated by admin.');
    }
    logActivity(auth.userId, 'admin_spin_activate', { is_active, daily_limit });
    return json(res, 200, { message: 'Spin settings updated' });
  }

  if (req.method === 'GET' && url.pathname === '/admin/dashboard') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });

    const users = db.prepare(`SELECT id, name, email, wallet_balance, is_admin, created_at, last_login_at
      FROM users ORDER BY created_at DESC`).all();

    const authActivity = db.prepare(`SELECT al.id, al.action, al.created_at, u.id as user_id, u.name, u.email
      FROM activity_logs al
      LEFT JOIN users u ON u.id = al.user_id
      WHERE al.action IN ('signup', 'login')
      ORDER BY al.created_at DESC
      LIMIT 100`).all();

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
    const rows = db.prepare(`SELECT sr.id, u.email, s.stock_name, sr.rating, sr.review_text, sr.created_at
      FROM stock_reviews sr
      JOIN users u ON u.id = sr.user_id
      JOIN stocks s ON s.id = sr.stock_id
      ORDER BY sr.created_at DESC`).all();
    return json(res, 200, { reviews: rows });
  }

  if (req.method === 'GET' && url.pathname === '/admin/activity-logs') {
    const auth = authUser(req);
    if (!auth || !auth.isAdmin) return json(res, 403, { error: 'Admin only' });
    const rows = db.prepare('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 200').all();
    return json(res, 200, { logs: rows.map((l) => ({ ...l, metadata: l.metadata ? JSON.parse(l.metadata) : null })) });
  }

  json(res, 404, { error: 'Not Found' });
}

const server = http.createServer((req, res) => {
  route(req, res).catch((error) => {
    json(res, 500, { error: 'Internal server error', detail: error.message });
  });
});

server.listen(PORT, () => {
  console.log(`Fidelity backend listening on http://localhost:${PORT}`);
});
