// "The Warden" — Discord OAuth login gate for the Facility Log admin console.
// Single-owner gate: no guild/role lookup, just checks that the logged-in
// Discord account matches OWNER_DISCORD_ID. Lets the DM post a new Facility
// Log entry after each session without a git commit + wrangler deploy --
// entries live in HARDTIMES_LOG KV and /api/log serves them to index.html.

const SITE_URL = 'https://hardtimes.919gaming.com/';
const COOKIE_NAME = 'warden_auth';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 14; // 14 days
const STATE_COOKIE_NAME = 'warden_oauth_state';
const STATE_COOKIE_PATH = '/warden';
const CONSOLE_PATH = '/warden/console';
const CALLBACK_PATH = '/warden/callback';
const REDIRECT_URI = 'https://hardtimes.919gaming.com' + CALLBACK_PATH;

const DISCORD_CLIENT_ID = '1527701783219142707';
const OWNER_DISCORD_ID = '161833822307090432';
const LOG_KV_KEY = 'log';

function b64urlEncode(buf) {
  let bin = '';
  new Uint8Array(buf).forEach(b => { bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBuf(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf;
}
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function signToken(payloadObj, secret) {
  const payload = b64urlEncode(new TextEncoder().encode(JSON.stringify(payloadObj)));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return payload + '.' + b64urlEncode(sig);
}
async function verifyToken(token, secret) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const key = await hmacKey(secret);
  const valid = await crypto.subtle.verify('HMAC', key, b64urlToBuf(sig), new TextEncoder().encode(payload));
  if (!valid) return null;
  try {
    const obj = JSON.parse(new TextDecoder().decode(b64urlToBuf(payload)));
    if (obj.exp && obj.exp < Math.floor(Date.now() / 1000)) return null;
    return obj;
  } catch (e) {
    return null;
  }
}
function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function getSession(request, env) {
  const authSecret = await env.AUTH_SECRET.get();
  const session = await verifyToken(getCookie(request, COOKIE_NAME), authSecret);
  if (!session || !session.id) return { loggedIn: false, discordId: null, username: null };
  return { loggedIn: true, discordId: session.id, username: session.username };
}
function isOwner(session) {
  return session.loggedIn && session.discordId === OWNER_DISCORD_ID;
}

const DEFAULT_LOG = [
  { date: 'Session 0', status: 'INTAKE', title: 'Orientation Complete',
    body: 'Six new case files logged, six new faces added to The Rock\'s population. Session One is loading — check back soon for the first word from inside.' }
];

async function getLogEntries(env) {
  const stored = await env.HARDTIMES_LOG.get(LOG_KV_KEY);
  if (!stored) return DEFAULT_LOG;
  try {
    return JSON.parse(stored);
  } catch (e) {
    return DEFAULT_LOG;
  }
}
async function saveLogEntries(env, entries) {
  await env.HARDTIMES_LOG.put(LOG_KV_KEY, JSON.stringify(entries));
}

function page(title, bodyHtml) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Big+Shoulders+Stencil:wght@600;800&family=Oswald:wght@400;500;600;700&family=Barlow:wght@400;500;600&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
  :root{ --void:#05060a; --panel:#12151f; --steel:#232733; --steel-lt:#4a5568;
    --amber:#ffb020; --amber-dim:#b9791a; --text:#d8dbe2; --text-dim:#8890a0; }
  *{ box-sizing:border-box; }
  body{ margin:0; min-height:100vh; background:var(--void); color:var(--text);
    font-family:'Barlow',sans-serif; line-height:1.6; padding:40px 20px; }
  .wrap{ max-width:640px; margin:0 auto; }
  h1{ font-family:'Big Shoulders Stencil',sans-serif; font-weight:800; font-size:36px; margin:0 0 4px; color:var(--text); }
  p.sub{ font-family:'Share Tech Mono',monospace; font-size:12px; letter-spacing:0.16em; text-transform:uppercase;
    color:var(--amber-dim); margin:0 0 30px; }
  .panel{ background:var(--panel); border:1px solid rgba(255,176,32,0.18); border-radius:6px; padding:26px 28px; margin-bottom:22px; }
  .panel h2{ font-family:'Oswald',sans-serif; font-weight:600; font-size:16px; letter-spacing:0.06em;
    text-transform:uppercase; color:var(--amber); margin:0 0 16px; }
  label{ display:block; font-family:'Share Tech Mono',monospace; font-size:11px; letter-spacing:0.08em;
    text-transform:uppercase; color:var(--text-dim); margin:14px 0 6px; }
  label:first-child{ margin-top:0; }
  input[type=text], textarea{ width:100%; background:var(--void); border:1px solid var(--steel-lt); border-radius:4px;
    color:var(--text); font-family:'Barlow',sans-serif; font-size:15px; padding:10px 12px; }
  textarea{ min-height:110px; resize:vertical; }
  input[type=text]:focus, textarea:focus{ outline:none; border-color:var(--amber); }
  button, .btn{ font-family:'Oswald',sans-serif; font-weight:600; font-size:13px; letter-spacing:0.06em;
    text-transform:uppercase; padding:10px 18px; border-radius:4px; border:none; cursor:pointer;
    background:var(--amber); color:#1a1305; margin-top:18px; }
  button:hover, .btn:hover{ filter:brightness(1.08); }
  .btn-danger{ background:none; border:1px solid rgba(220,80,80,0.5); color:#e08a8a; padding:6px 12px;
    font-size:11px; margin:0; }
  .btn-danger:hover{ background:rgba(220,80,80,0.12); filter:none; }
  .entry{ padding:14px 0; border-bottom:1px solid rgba(74,85,104,0.3); display:flex; justify-content:space-between; gap:12px; align-items:flex-start; }
  .entry:last-child{ border-bottom:none; }
  .entry .meta{ font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--amber-dim); margin:0 0 4px; }
  .entry h3{ font-family:'Oswald',sans-serif; font-size:15px; margin:0 0 4px; color:var(--text); }
  .entry p{ font-size:13.5px; color:var(--text-dim); margin:0; }
  .nav-row{ display:flex; justify-content:space-between; margin-top:26px; }
  .nav-row a{ font-family:'Share Tech Mono',monospace; font-size:11px; letter-spacing:0.1em; text-transform:uppercase;
    color:var(--text-dim); text-decoration:none; }
  .nav-row a:hover{ color:var(--amber); }
  .msg{ font-family:'Share Tech Mono',monospace; font-size:13px; color:var(--text-dim); margin:0 0 20px; }
</style></head><body><div class="wrap">${bodyHtml}</div></body></html>`;
}

function errorPage(title, message) {
  return page(title, `
    <h1>${escapeHtml(title)}</h1>
    <p class="msg">${escapeHtml(message)}</p>
    <div class="nav-row"><a href="${SITE_URL}">&larr; Back to site</a></div>
  `);
}

function consolePage(entries) {
  const rows = entries.length
    ? entries.map((e, i) => `
      <div class="entry">
        <div>
          <p class="meta">${escapeHtml(e.date)} &middot; ${escapeHtml(e.status)}</p>
          <h3>${escapeHtml(e.title)}</h3>
          <p>${escapeHtml(e.body)}</p>
        </div>
        <form method="POST" action="${CONSOLE_PATH}/delete" onsubmit="return confirm('Delete this entry?')">
          <input type="hidden" name="index" value="${i}">
          <button type="submit" class="btn-danger">Delete</button>
        </form>
      </div>`).join('')
    : '<p class="msg">No entries yet.</p>';

  return page("Hard Times — Warden's Console", `
    <h1>Warden's Console</h1>
    <p class="sub">Facility Log admin</p>

    <div class="panel">
      <h2>Post New Entry</h2>
      <form method="POST" action="${CONSOLE_PATH}">
        <label for="date">Date label</label>
        <input type="text" id="date" name="date" placeholder="Session 4 &middot; 2026-07-20" required>
        <label for="status">Status tag</label>
        <input type="text" id="status" name="status" placeholder="RECAP / TEASER / SIDE QUEST" required>
        <label for="title">Title</label>
        <input type="text" id="title" name="title" required>
        <label for="body">Body</label>
        <textarea id="body" name="body" required></textarea>
        <button type="submit">Post to Facility Log</button>
      </form>
    </div>

    <div class="panel">
      <h2>Current Entries</h2>
      ${rows}
    </div>

    <div class="nav-row">
      <a href="${SITE_URL}">&larr; Back to site</a>
      <a href="/warden/logout">Log out</a>
    </div>
  `);
}

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'"
].join('; ');

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('Content-Security-Policy', CSP);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const html = { 'content-type': 'text/html;charset=UTF-8', 'cache-control': 'no-store, private' };

  if (url.pathname === '/api/log' && request.method === 'GET') {
    const entries = await getLogEntries(env);
    return new Response(JSON.stringify(entries), {
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
    });
  }

  if (url.pathname === '/warden' && request.method === 'GET') {
    const existingSession = await getSession(request, env);
    if (isOwner(existingSession)) {
      return Response.redirect(url.origin + CONSOLE_PATH, 302);
    }
    const state = crypto.randomUUID();
    const authorizeUrl = new URL('https://discord.com/api/oauth2/authorize');
    authorizeUrl.searchParams.set('client_id', DISCORD_CLIENT_ID);
    authorizeUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('scope', 'identify');
    authorizeUrl.searchParams.set('state', state);
    const headers = new Headers({ Location: authorizeUrl.toString(), 'Cache-Control': 'no-store, private' });
    headers.append('Set-Cookie', `${STATE_COOKIE_NAME}=${state}; Path=${STATE_COOKIE_PATH}; Max-Age=300; HttpOnly; Secure; SameSite=Lax`);
    return new Response(null, { status: 302, headers });
  }

  if (url.pathname === CALLBACK_PATH && request.method === 'GET') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const savedState = getCookie(request, STATE_COOKIE_NAME);
    const clearState = `${STATE_COOKIE_NAME}=; Path=${STATE_COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;

    if (!code || !state || !savedState || state !== savedState) {
      const headers = new Headers(html);
      headers.append('Set-Cookie', clearState);
      return new Response(errorPage('Login Failed', 'That login link expired or was invalid. Please try again.'), { status: 400, headers });
    }

    const clientSecret = await env.DISCORD_CLIENT_SECRET.get();
    const tokenRes = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI
      })
    });
    if (!tokenRes.ok) {
      const headers = new Headers(html);
      headers.append('Set-Cookie', clearState);
      return new Response(errorPage('Login Failed', 'Discord rejected that login attempt.'), { status: 401, headers });
    }
    const { access_token } = await tokenRes.json();

    const userRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const user = await userRes.json();

    if (user.id !== OWNER_DISCORD_ID) {
      const headers = new Headers(html);
      headers.append('Set-Cookie', clearState);
      return new Response(errorPage('Access Denied', 'This Discord account is not authorized for the Warden console.'), { status: 403, headers });
    }

    const exp = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
    const authSecret = await env.AUTH_SECRET.get();
    const token = await signToken({ id: user.id, username: user.username, exp }, authSecret);
    const headers = new Headers({ Location: url.origin + CONSOLE_PATH, 'Cache-Control': 'no-store, private' });
    headers.append('Set-Cookie', `${COOKIE_NAME}=${token}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`);
    headers.append('Set-Cookie', clearState);
    return new Response(null, { status: 302, headers });
  }

  if (url.pathname === '/warden/logout') {
    const headers = new Headers({ Location: SITE_URL, 'Cache-Control': 'no-store, private' });
    headers.append('Set-Cookie', `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
    return new Response(null, { status: 302, headers });
  }

  if (url.pathname === CONSOLE_PATH && request.method === 'GET') {
    const session = await getSession(request, env);
    if (!isOwner(session)) {
      return Response.redirect(url.origin + '/warden', 302);
    }
    const entries = await getLogEntries(env);
    return new Response(consolePage(entries), { headers: html });
  }

  if (url.pathname === CONSOLE_PATH && request.method === 'POST') {
    const session = await getSession(request, env);
    if (!isOwner(session)) {
      return Response.redirect(url.origin + '/warden', 302);
    }
    const form = await request.formData();
    const date = (form.get('date') || '').toString().trim();
    const status = (form.get('status') || '').toString().trim();
    const title = (form.get('title') || '').toString().trim();
    const body = (form.get('body') || '').toString().trim();
    if (!date || !status || !title || !body) {
      return Response.redirect(url.origin + CONSOLE_PATH, 302);
    }
    const entries = await getLogEntries(env);
    entries.unshift({ date, status, title, body });
    await saveLogEntries(env, entries);
    return Response.redirect(url.origin + CONSOLE_PATH, 302);
  }

  if (url.pathname === CONSOLE_PATH + '/delete' && request.method === 'POST') {
    const session = await getSession(request, env);
    if (!isOwner(session)) {
      return Response.redirect(url.origin + '/warden', 302);
    }
    const form = await request.formData();
    const index = parseInt((form.get('index') || '').toString(), 10);
    const entries = await getLogEntries(env);
    if (Number.isInteger(index) && index >= 0 && index < entries.length) {
      entries.splice(index, 1);
      await saveLogEntries(env, entries);
    }
    return Response.redirect(url.origin + CONSOLE_PATH, 302);
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env, ctx) {
    return withSecurityHeaders(await handleRequest(request, env, ctx));
  }
};
