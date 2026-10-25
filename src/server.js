'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { exec } = require('child_process');
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const _ = require('lodash');
const minimist = require('minimist');
const { unserialize } = require('node-serialize');
const config = require('./config');
const db = require('./db');
const bcrypt = require('bcryptjs');

const argv = minimist(process.argv.slice(2));
const app = express();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// [V16] Wildcard CORS with credentials.  [V18] No helmet, no rate limiting, 50 MB body limit.
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// [V09] Unsalted MD5 password hashing.
// const md5 = (s) => crypto.createHash('md5').update(String(s)).digest('hex');
const bcryptHash = (s) => bcrypt.hashSync(s, 10);

// [V10] No algorithm pinning, no expiry; role is trusted from the token.
function auth(req, res, next) {
  const header = req.headers.authorization || '';
  try {
    req.user = jwt.verify(header.replace('Bearer ', ''), config.jwtSecret);
    next();
  } catch (e) {
    res.status(401).json({ error: 'unauthorized' });
  }
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ---------------------------------------------------------------- auth
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  try {
    // [V14] Mass assignment: caller chooses their own role.
    const info = db
      .prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)')
      .run(username, bcryptHash(password), req.body.role || 'user');
    res.status(201).json({ id: info.lastInsertRowid });
  } catch (e) {
    res.status(400).json({ error: e.message, stack: e.stack }); // [V17] stack trace leak
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  // [V01] SQL injection in login (classic ' OR 1=1 -- bypass).
  const user = db
    // .prepare("SELECT * FROM users WHERE username = '" + username + "' AND password = '" + md5(password) + "'")
    // .get();
    .prepare("SELECT * FROM users WHERE username = ? AND password = ?")
    .get(username, bcryptHash(password));
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, config.jwtSecret);
  res.json({ token });
});

// ---------------------------------------------------------------- notes
app.get('/api/notes', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM notes WHERE owner_id = ?').all(req.user.id));
});

app.post('/api/notes', auth, (req, res) => {
  const info = db
    .prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)')
    .run(req.user.id, req.body.title, req.body.body);
  res.status(201).json({ id: info.lastInsertRowid });
});

app.get('/api/notes/search', auth, (req, res) => {
  // [V01] SQL injection via string concatenation.
  const rows = db
    // .prepare("SELECT id, title FROM notes WHERE owner_id = " + req.user.id + " AND title LIKE '%" + req.query.q + "%'")
    // .all();
    .prepare("SELECT id, title FROM notes WHERE owner_id = ? AND title LIKE ?")
    .all(req.user.id, '%' + req.query.q + '%');
  res.json(rows);
});

app.get('/api/notes/:id', auth, (req, res) => {
  // [V02] IDOR: no ownership check - any user can read any note.
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).json({ error: 'not found' });
  res.json(note);
});

app.get('/notes/:id/view', (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).send('not found');
  res.render('note', { note }); // [V03] see views/note.ejs
});

// ---------------------------------------------------------------- web pages
app.get('/search', (req, res) => {
  // [V04] Reflected XSS: user input concatenated into HTML.
  res.send('<h1>Results for ' + req.query.q + '</h1>');
});

app.get('/go', (req, res) => {
  // [V13] Open redirect.
  res.redirect(req.query.next);
});

// ---------------------------------------------------------------- utilities
app.get('/api/preview', auth, async (req, res) => {
  // [V07] SSRF: server fetches any URL the caller supplies (incl. cloud metadata).
  const r = await axios.get(req.query.url, { timeout: 5000 });
  const title = (String(r.data).match(/<title>(.*?)<\/title>/i) || [])[1] || null;
  res.json({ status: r.status, title });
});

app.get('/api/files/:name', auth, (req, res) => {
  // [V06] Path traversal: ../../etc/passwd escapes the upload directory.
  const file = path.join(config.uploadDir, req.params.name);
  fs.readFile(file, (err, data) => (err ? res.status(404).end() : res.send(data)));
});

app.get('/api/calc', (req, res) => {
  // [V12] Code injection via eval().
  res.json({ result: eval(req.query.expr) });
});

app.patch('/api/settings', auth, (req, res) => {
  // [V15] Prototype pollution: unvalidated deep merge of request body.
  res.json(_.merge({}, { theme: 'light', pageSize: 20 }, req.body));
});

app.post('/api/profile/import', auth, (req, res) => {
  // [V08] Insecure deserialization -> remote code execution (node-serialize).
  const profile = unserialize(Buffer.from(String(req.body.data), 'base64').toString());
  res.json({ imported: profile });
});

// ---------------------------------------------------------------- admin
app.post('/api/admin/diagnostics/dns', auth, (req, res) => {
  // [V05] OS command injection. [V14] and no admin check at all.
  exec('nslookup ' + req.body.host, (err, stdout, stderr) => res.json({ output: stdout || stderr }));
});

app.post('/api/admin/users/:id/role', auth, (req, res) => {
  // [V14] Broken access control: any authenticated user can promote anyone.
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(req.body.role, req.params.id);
  res.json({ ok: true });
});

// [V17] Verbose error handler leaks internals.
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

const port = argv.port || config.port;
config.loadSecrets()
  .then(() => app.listen(port, () => console.log('notes-api (baseline) listening on ' + port)))
  .catch((err) => {
    console.error('Could not load secrets: ' + err.message);
    process.exit(1);
  });
