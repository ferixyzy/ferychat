// TsynchaT server: static site + username/password auth (no dependencies).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const PUB = path.join(__dirname, 'public');
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB = path.join(DATA, 'db.json');
fs.mkdirSync(DATA, { recursive: true });
let db = { users: [], sessions: {}, seq: 1000 };
try { db = JSON.parse(fs.readFileSync(DB, 'utf8')); } catch {}
const save = () => { fs.writeFileSync(DB + '.tmp', JSON.stringify(db)); fs.renameSync(DB + '.tmp', DB); };

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.jpg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml', '.json': 'application/json', '.ico': 'image/x-icon', '.webp': 'image/webp' };
const json = (res, code, obj, h = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...h }); res.end(JSON.stringify(obj)); };
const pub = u => ({ id: u.id, username: u.username, nickname: u.nickname || u.username, avatar: u.avatar || null, bio: u.bio || '', createdAt: u.createdAt });
const hash = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 64).toString('hex');
const verify = (pw, h) => { const [salt, k] = h.split(':'); const a = Buffer.from(k, 'hex'), b = crypto.scryptSync(pw, salt, 64); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map(c => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
const me = req => { const t = cookie(req).tsyn_session; const id = t && db.sessions[t]; return id && db.users.find(u => u.id === id); };
const setCookie = (req, t, maxAge) => `tsyn_session=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}` + (req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '');
const body = req => new Promise(r => { let d = ''; req.on('data', c => { d += c; if (d.length > 1e6) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(d || '{}')); } catch { r({}); } }); });

const tries = new Map();
const limited = ip => { const now = Date.now(), a = (tries.get(ip) || []).filter(t => now - t < 600000); a.push(now); tries.set(ip, a); return a.length > 30; };

async function api(req, res, url) {
  const p = url.pathname, q = url.searchParams, user = me(req);
  if (p === '/api/auth/providers') return json(res, 200, { google: false });
  if (p === '/api/users') {
    if (req.method === 'POST') {
      const b = await body(req);
      if (b.action === 'logout') {
        const t = cookie(req).tsyn_session; if (t) { delete db.sessions[t]; save(); }
        return json(res, 200, { ok: true }, { 'Set-Cookie': setCookie(req, '', 0) });
      }
      if (b.website) return json(res, 400, { error: 'Request rejected' });
      const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
      if (limited(ip)) return json(res, 429, { error: 'Too many attempts. Please wait a bit.' });
      const username = String(b.username || '').trim().toLowerCase().replace(/^@/, ''), password = String(b.password || '');
      if (!username || !password) return json(res, 400, { error: 'Enter your username and password' });
      let u;
      if (b.action === 'register') {
        if (!/^[a-z0-9_]{3,32}$/.test(username)) return json(res, 400, { error: 'Username: 3 to 32 characters, a-z, 0-9 and _ only' });
        if (password.length < 6 || password.length > 200) return json(res, 400, { error: 'Password must be at least 6 characters' });
        if (db.users.some(x => x.username === username)) return json(res, 409, { error: 'That username is taken' });
        u = { id: String(++db.seq), username, nickname: username, avatar: null, createdAt: Date.now(), password: hash(password) };
        db.users.push(u);
      } else {
        u = db.users.find(x => x.username === username);
        if (!u || !verify(password, u.password)) return json(res, 401, { error: 'Wrong username or password' });
      }
      const t = crypto.randomBytes(32).toString('hex'); db.sessions[t] = u.id; save();
      return json(res, 200, { user: pub(u) }, { 'Set-Cookie': setCookie(req, t, 60 * 60 * 24 * 90) });
    }
    if (req.method === 'PATCH') {
      if (!user) return json(res, 401, { error: 'Please sign in again' });
      const b = await body(req);
      if (b.username !== undefined) {
        const n = String(b.username).trim().toLowerCase();
        if (!/^[a-z0-9_]{3,32}$/.test(n)) return json(res, 400, { error: 'Invalid username' });
        if (db.users.some(x => x.username === n && x.id !== user.id)) return json(res, 409, { error: 'That username is taken' });
        user.username = n;
      }
      for (const k of ['nickname', 'bio', 'avatar']) if (typeof b[k] === 'string') user[k] = b[k].slice(0, k === 'avatar' ? 2e5 : 200);
      if (b.password) { if (String(b.password).length < 6) return json(res, 400, { error: 'Password must be at least 6 characters' }); user.password = hash(String(b.password)); }
      save(); return json(res, 200, pub(user));
    }
    if (q.get('me')) return user ? json(res, 200, pub(user)) : json(res, 401, { error: 'Not signed in' });
    if (!user) return json(res, 401, { error: 'Please sign in again' });
    if (q.get('id')) { const u = db.users.find(x => x.id === q.get('id')); return u ? json(res, 200, pub(u)) : json(res, 404, { error: 'Not found' }); }
    if (q.get('username')) { const u = db.users.find(x => x.username === q.get('username').toLowerCase()); return u ? json(res, 200, pub(u)) : json(res, 404, { error: 'Not found' }); }
    return json(res, 200, db.users.filter(u => u.id !== q.get('exclude')).map(pub));
  }
  // Chat/group/channel APIs are not part of the cloned front end.
  if (req.method === 'GET') return json(res, 200, []);
  return json(res, 501, { error: 'This feature is not available on this server yet' });
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    const rel = decodeURIComponent(url.pathname).replace(/\/+$/, '') || '/index.html';
    const f = path.normalize(path.join(PUB, rel));
    if (!f.startsWith(PUB)) { res.writeHead(403); return res.end(); }
    let hit = [f, f + '.html', path.join(f, 'index.html')].find(c => fs.existsSync(c) && fs.statSync(c).isFile());
    if (!hit && /^\/(channel|groupchat)\//.test(rel)) hit = path.join(PUB, rel.startsWith('/channel') ? 'channel/tsynchat.html' : 'groupchat/tsynchat_group.html');
    if (!hit) hit = path.join(PUB, 'index.html');
    const ext = path.extname(hit);
    res.writeHead(200, { 'Content-Type': MIME[ext] || (ext ? 'application/octet-stream' : 'text/html; charset=utf-8'), 'Cache-Control': hit.includes('/_next/static/') ? 'public, max-age=31536000, immutable' : 'no-cache' });
    fs.createReadStream(hit).pipe(res);
  } catch (e) { console.error(e); json(res, 500, { error: 'Server error' }); }
}).listen(PORT, () => console.log('TsynchaT running on http://localhost:' + PORT));
