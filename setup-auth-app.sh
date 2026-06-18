usr/bin/env bash
set -e
echo "Creating auth-app files..."
mkdir -p auth-app/{public,migrations,routes}
mkdir -p scripts
mkdir -p .github/workflows

cat > auth-app/package.json <<'JSON'
{
  "name": "base44-auth-app",
  "version": "1.0.0",
  "description": "Simple auth app (signup/login) using Turso placeholders",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "migrate": "node ../scripts/migrate.js",
    "zip": "zip -r website_scrape.zip auth-app/"
  },
  "dependencies": {
    "@libsql/client": "^0.5.0",
    "bcrypt": "^5.1.0",
    "cookie-parser": "^1.4.6",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "uuid": "^9.0.0"
  }
}
JSON

cat > auth-app/server.js <<'JS'
const express = require('express');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use('/api', authRoutes);
app.use(express.static('auth-app/public'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth app listening on ${PORT}`));
JS

cat > auth-app/db.js <<'JS'
const { createClient } = require('@libsql/client');

const url = process.env.TURSO_DATABASE_URL || process.env.DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN || process.env.DATABASE_AUTH_TOKEN;

if (!url) {
  console.warn('TURSO_DATABASE_URL / DATABASE_URL not set — DB client will fail until configured');
}

const client = createClient({ url, auth: { token: authToken } });

async function execute(sql, args = []) {
  const r = await client.execute({ sql, args });
  return r.rows || [];
}

module.exports = { execute };
JS

cat > scripts/migrate.js <<'JS'
const fs = require('fs');
const path = require('path');
const db = require('../auth-app/db');

async function migrate() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'auth-app', 'migrations', 'init.sql'), 'utf8');
  const stmts = sql.split(/;\s*\n/).map(s => s.trim()).filter(Boolean);
  for (const s of stmts) {
    console.log('Running:', s.slice(0, 80));
    await db.execute(s);
  }
  console.log('Migration complete');
}

migrate().catch(err => { console.error(err); process.exit(1); });
JS

cat > auth-app/migrations/init.sql <<'SQL'
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  reset_token TEXT,
  reset_expires INTEGER,
  remember_token TEXT,
  created_at INTEGER NOT NULL
);
SQL

cat > auth-app/routes/auth.js <<'JS'
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');

const router = express.Router();

const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET || 'dev-access-secret';
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || 'dev-refresh-secret';

function signAccess(payload) {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: '15m' });
}

function signRefresh(payload, remember) {
  const opts = remember ? { expiresIn: '30d' } : undefined;
  return jwt.sign(payload, REFRESH_SECRET, opts);
}

router.post('/signup', async (req, res) => {
  const { email, password, remember } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  const existing = await db.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
  if (existing[0]) return res.status(409).json({ error: 'Email already in use' });
  const hash = await bcrypt.hash(password, 10);
  const id = uuidv4();
  const now = Math.floor(Date.now()/1000);
  await db.execute('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)', [id, email, hash, now]);
  const access = signAccess({ sub: id });
  const refresh = signRefresh({ sub: id }, remember);
  res.cookie('access_token', access, { httpOnly: true, sameSite: 'lax' });
  const cookieOpts = { httpOnly: true, sameSite: 'lax' };
  if (remember) cookieOpts.maxAge = 30 * 24 * 60 * 60 * 1000;
  res.cookie('refresh_token', refresh, cookieOpts);
  res.json({ success: true });
});

router.post('/login', async (req, res) => {
  const { email, password, remember } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  const rows = await db.execute('SELECT id, password_hash FROM users WHERE email = ? LIMIT 1', [email]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const access = signAccess({ sub: user.id });
  const refresh = signRefresh({ sub: user.id }, remember);
  res.cookie('access_token', access, { httpOnly: true, sameSite: 'lax' });
  const cookieOpts = { httpOnly: true, sameSite: 'lax' };
  if (remember) cookieOpts.maxAge = 30 * 24 * 60 * 60 * 1000;
  res.cookie('refresh_token', refresh, cookieOpts);
  res.json({ success: true });
});

router.post('/logout', (req, res) => {
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  res.json({ success: true });
});

router.post('/refresh', (req, res) => {
  const token = req.cookies['refresh_token'];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, REFRESH_SECRET);
    const access = signAccess({ sub: payload.sub });
    res.cookie('access_token', access, { httpOnly: true, sameSite: 'lax' });
    return res.json({ success: true });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
});

router.post('/forgot', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  const rows = await db.execute('SELECT id FROM users WHERE email = ? LIMIT 1', [email]);
  const user = rows[0];
  if (!user) return res.json({ success: true });
  const token = uuidv4();
  const expires = Math.floor(Date.now()/1000) + 60*60;
  await db.execute('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?', [token, expires, user.id]);
  res.json({ success: true, resetToken: token });
});

router.post('/reset', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Missing token or password' });
  const rows = await db.execute('SELECT id, reset_expires FROM users WHERE reset_token = ? LIMIT 1', [token]);
  const user = rows[0];
  if (!user) return res.status(400).json({ error: 'Invalid token' });
  if (user.reset_expires < Math.floor(Date.now()/1000)) return res.status(400).json({ error: 'Token expired' });
  const hash = await bcrypt.hash(password, 10);
  await db.execute('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?', [hash, user.id]);
  res.json({ success: true });
});

router.get('/me', async (req, res) => {
  const token = req.cookies['access_token'];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, ACCESS_SECRET);
    const rows = await db.execute('SELECT id, email, created_at FROM users WHERE id = ? LIMIT 1', [payload.sub]);
    const user = rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

module.exports = router;
JS

cat > auth-app/public/signup.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8" /><title>Sign up</title></head>
  <body>
    <h1>Sign up</h1>
    <form id="signup">
      <input type="email" id="email" placeholder="Email" required /><br/>
      <input type="password" id="password" placeholder="Password" required /><br/>
      <label><input type="checkbox" id="remember" /> Remember me</label><br/>
      <button type="submit">Sign up</button>
    </form>
    <p>Already? <a href="/login.html">Login</a></p>
    <script>
      document.getElementById('signup').addEventListener('submit', async e => {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember').checked;
        const r = await fetch('/api/signup', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password,remember})});
        if (r.ok) location.href = '/dashboard.html'; else alert(JSON.stringify(await r.json()));
      });
    </script>
  </body>
</html>
HTML

cat > auth-app/public/login.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8" /><title>Login</title></head>
  <body>
    <h1>Login</h1>
    <form id="login">
      <input type="email" id="email" placeholder="Email" required /><br/>
      <input type="password" id="password" placeholder="Password" required /><br/>
      <label><input type="checkbox" id="remember" /> Remember me</label><br/>
      <button type="submit">Login</button>
    </form>
    <p><a href="/forgot.html">Forgot?</a> • <a href="/signup.html">Sign up</a></p>
    <script>
      document.getElementById('login').addEventListener('submit', async e => {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const remember = document.getElementById('remember').checked;
        const r = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password,remember})});
        if (r.ok) location.href = '/dashboard.html'; else alert(JSON.stringify(await r.json()));
      });
    </script>
  </body>
</html>
HTML

cat > auth-app/public/dashboard.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8" /><title>Dashboard</title></head>
  <body>
    <h1>Dashboard</h1>
    <pre id="info">Loading...</pre>
    <button id="logout">Logout</button>
    <script>
      async function load() {
        const r = await fetch('/api/me');
        if (!r.ok) return location.href = '/login.html';
        const j = await r.json();
        document.getElementById('info').innerText = JSON.stringify(j.user, null, 2);
      }
      document.getElementById('logout').addEventListener('click', async () => {
        await fetch('/api/logout', {method:'POST'});
        location.href = '/login.html';
      });
      load();
    </script>
  </body>
</html>
HTML

cat > auth-app/public/forgot.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8" /><title>Forgot</title></head>
  <body>
    <h1>Forgot</h1>
    <form id="forgot"><input type="email" id="email" placeholder="Email" required /><button>Send</button></form>
    <div id="result"></div>
    <script>
      document.getElementById('forgot').addEventListener('submit', async e => {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const r = await fetch('/api/forgot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});
        const j = await r.json();
        if (r.ok) document.getElementById('result').innerText = 'Reset token (for testing): ' + (j.resetToken || '');
      });
    </script>
  </body>
</html>
HTML

cat > auth-app/public/forgot-reset.html <<'HTML'
<!doctype html>
<html>
  <head><meta charset="utf-8" /><title>Reset</title></head>
  <body>
    <h1>Reset</h1>
    <form id="reset">
      <input id="token" placeholder="Token" required /><br/>
      <input id="password" placeholder="New password" required /><br/>
      <button>Reset</button>
    </form>
    <script>
      document.getElementById('reset').addEventListener('submit', async e => {
        e.preventDefault();
        const token = document.getElementById('token').value;
        const password = document.getElementById('password').value;
        const r = await fetch('/api/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,password})});
        if (r.ok) alert('OK, log in'); else alert(JSON.stringify(await r.json()));
      });
    </script>
  </body>
</html>
HTML

cat > auth-app/README.md <<'MD'
# Base44 Auth App

Node.js + Express auth app (Turso-ready). See root README for usage.
MD

cat > auth-app/.env.example <<'ENV'
TURSO_DATABASE_URL=
TURSO_AUTH_TOKEN=
ACCESS_TOKEN_SECRET=change-me
REFRESH_TOKEN_SECRET=change-me
PORT=3000
ENV

cat > auth-app/.gitignore <<'GIT'
node_modules
.env
auth-app/website_scrape.zip
GIT

cat > website_scrape.zip <<'TXT'
Placeholder: run `zip -r website_scrape.zip auth-app/` to create zip
TXT

cat > .github/workflows/build-zip.yml <<'YML'
name: Build and commit auth-app zip

on:
  push:
    paths:
      - 'auth-app/**'
      - '.github/workflows/build-zip.yml'

jobs:
  build-zip:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install zip
        run: sudo apt-get update && sudo apt-get install -y zip
      - name: Create zip
        run: zip -r website_scrape.zip auth-app/
      - name: Commit zip
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add website_scrape.zip
          git commit -m "ci: update website_scrape.zip (auth-app)" || echo "no changes"
          git push
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
YML

echo "Setup files written."
