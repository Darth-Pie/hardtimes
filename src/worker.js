// "The Warden" — Discord login gate for the Facility Log.
// Four tiers:
//   - God (hardcoded OWNER_DISCORD_ID): full control, can post entries that
//     go live immediately, edit/delete any entry, approve/reject pending
//     submissions, manage (block/remove/revoke-sessions) any account, assign
//     characters, and grant/revoke the Moderator flag.
//   - Moderator (any account with isModerator:true, set by God -- not tied
//     to a Discord role): same day-to-day powers as God over entries and
//     accounts, except a moderator can't act on God's account or another
//     moderator's account, and only God can grant/revoke the flag itself.
//   - Contributor (anyone holding CONTRIBUTOR_ROLE_ID in GUILD_ID): can log
//     in and submit new entries, which land as "pending" until a God/
//     Moderator approves them.
//   - Member (logged in, in GUILD_ID, but holds neither of the above):
//     can log in and appear in Accounts, but can't submit entries yet --
//     groundwork for a future member hub.
// Session cookie carries only identity + a session epoch -- role/blocked/
// moderator status is looked up fresh from HARDTIMES_USERS on every
// request, and a mismatched epoch (bumped via "revoke sessions") logs the
// cookie out immediately, same as a block does.

const SITE_URL = 'https://hardtimes.919gaming.com/';
const COOKIE_NAME = 'warden_auth';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 14; // 14 days
const STATE_COOKIE_NAME = 'warden_oauth_state';
const STATE_COOKIE_PATH = '/warden';
const CALLBACK_PATH = '/warden/callback';
const REDIRECT_URI = 'https://hardtimes.919gaming.com' + CALLBACK_PATH;

const DISCORD_CLIENT_ID = '1527701783219142707';
const OWNER_DISCORD_ID = '161833822307090432';
const GUILD_ID = '223208136780152832';
const CONTRIBUTOR_ROLE_ID = '1516570040579657898';
const LOG_KV_KEY = 'log';
const USER_KEY_PREFIX = 'user:';
const AUDIT_KEY = 'audit_log';
const AUDIT_MAX = 200;

// Mirror of the `characters` array in index.html (name only) -- keep this
// list in sync when a character is added/renamed there. Used only to
// validate character-assignment requests; slugify() below must match
// index.html's slug logic exactly since the slug is the shared identifier.
const CHARACTER_NAMES = ['Kael', 'Mistarion', 'Heishi Kyu', 'Verum-Gaea', 'ND-E', 'Velveteen'];
function slugify(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}
const CHARACTERS = CHARACTER_NAMES.map(name => ({ slug: slugify(name), name }));

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
async function readJson(request) {
  try {
    return await request.json();
  } catch (e) {
    return null;
  }
}
function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
  });
}

async function getUserRecord(env, discordId) {
  const stored = await env.HARDTIMES_USERS.get(USER_KEY_PREFIX + discordId);
  return stored ? JSON.parse(stored) : null;
}
async function upsertUserRecord(env, { discordId, username, role }) {
  const existing = await getUserRecord(env, discordId);
  const now = Date.now();
  const record = {
    discordId,
    username,
    role,
    blocked: existing ? !!existing.blocked : false,
    isModerator: existing ? !!existing.isModerator : false,
    sessionEpoch: existing ? (existing.sessionEpoch || 0) : 0,
    characterSlug: existing ? (existing.characterSlug || null) : null,
    characterName: existing ? (existing.characterName || null) : null,
    firstLogin: existing ? existing.firstLogin : now,
    lastLogin: now
  };
  await env.HARDTIMES_USERS.put(USER_KEY_PREFIX + discordId, JSON.stringify(record));
  return record;
}
async function listUsers(env) {
  const { keys } = await env.HARDTIMES_USERS.list({ prefix: USER_KEY_PREFIX });
  const users = [];
  for (const k of keys) {
    const stored = await env.HARDTIMES_USERS.get(k.name);
    if (stored) users.push(JSON.parse(stored));
  }
  users.sort((a, b) => b.lastLogin - a.lastLogin);
  return users;
}

async function appendAudit(env, entry) {
  const stored = await env.HARDTIMES_USERS.get(AUDIT_KEY);
  let list;
  try { list = stored ? JSON.parse(stored) : []; } catch (e) { list = []; }
  list.unshift(entry);
  if (list.length > AUDIT_MAX) list.length = AUDIT_MAX;
  await env.HARDTIMES_USERS.put(AUDIT_KEY, JSON.stringify(list));
}
async function getAudit(env) {
  const stored = await env.HARDTIMES_USERS.get(AUDIT_KEY);
  try { return stored ? JSON.parse(stored) : []; } catch (e) { return []; }
}

// Session + live permission check, consolidated: verifies the cookie's
// signature, then re-reads the KV record every request so a block or a
// "revoke sessions" (session-epoch bump) takes effect on the very next
// request rather than waiting for the cookie to expire or for re-login.
async function getSession(request, env) {
  const authSecret = await env.AUTH_SECRET.get();
  const payload = await verifyToken(getCookie(request, COOKIE_NAME), authSecret);
  if (!payload || !payload.id) return { loggedIn: false, discordId: null, username: null, record: null };
  const record = await getUserRecord(env, payload.id);
  if (!record || record.blocked) return { loggedIn: false, discordId: null, username: null, record: null };
  if ((payload.epoch || 0) !== (record.sessionEpoch || 0)) {
    return { loggedIn: false, discordId: null, username: null, record: null };
  }
  return { loggedIn: true, discordId: payload.id, username: payload.username, record };
}

async function getPermissions(request, env) {
  const session = await getSession(request, env);
  if (!session.loggedIn) {
    return {
      loggedIn: false, discordId: null, username: null, role: null,
      isGod: false, isModerator: false, isContributor: false,
      canManage: false, canSubmit: false, characterSlug: null, characterName: null
    };
  }
  const record = session.record;
  const isGod = record.role === 'god';
  const isModerator = !isGod && !!record.isModerator;
  const isContributor = record.role === 'contributor';
  const canManage = isGod || isModerator;
  return {
    loggedIn: true,
    discordId: session.discordId,
    username: session.username,
    role: record.role,
    isGod, isModerator, isContributor,
    canManage,
    canSubmit: canManage || isContributor,
    characterSlug: record.characterSlug || null,
    characterName: record.characterName || null
  };
}

// Whether `perms` (already resolved via getPermissions) may act on
// `targetRecord`. God can act on anyone; a moderator can act on anyone
// except God or another moderator, so moderators can't lock each other
// (or God) out. Only God can grant/revoke the moderator flag itself.
function canActOnTarget(perms, targetRecord) {
  if (perms.isGod) return true;
  if (!perms.isModerator) return false;
  return targetRecord.role !== 'god' && !targetRecord.isModerator;
}

function normalizeEntry(e, i) {
  return {
    id: e.id || ('legacy-' + i),
    date: e.date, status: e.status, title: e.title, body: e.body,
    approved: e.approved !== undefined ? e.approved : true,
    authorId: e.authorId || null,
    authorName: e.authorName || null
  };
}
const DEFAULT_LOG = [
  { date: 'Session 0', status: 'INTAKE', title: 'Orientation Complete',
    body: 'Six new case files logged, six new faces added to The Rock\'s population. Session One is loading — check back soon for the first word from inside.' }
];
async function getLogEntries(env) {
  const stored = await env.HARDTIMES_LOG.get(LOG_KV_KEY);
  let entries;
  if (!stored) {
    entries = DEFAULT_LOG;
  } else {
    try { entries = JSON.parse(stored); } catch (e) { entries = DEFAULT_LOG; }
  }
  return entries.map(normalizeEntry);
}
async function saveLogEntries(env, entries) {
  await env.HARDTIMES_LOG.put(LOG_KV_KEY, JSON.stringify(entries));
}

function errorPage(title, message) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  body{ margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:#05060a; color:#d8dbe2; font-family:sans-serif; padding:24px; }
  .box{ max-width:420px; text-align:center; }
  h1{ color:#ffb020; font-size:22px; }
  a{ color:#ffb020; }
</style></head><body><div class="box">
  <h1>${escapeHtml(title)}</h1>
  <p>${escapeHtml(message)}</p>
  <p><a href="${SITE_URL}">&larr; Back to site</a></p>
</div></body></html>`;
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
  const htmlHeaders = { 'content-type': 'text/html;charset=UTF-8', 'cache-control': 'no-store, private' };

  // ---- session/status ----
  if (url.pathname === '/api/session' && request.method === 'GET') {
    const perms = await getPermissions(request, env);
    return json({
      loggedIn: perms.loggedIn, username: perms.username, role: perms.role,
      isGod: perms.isGod, isModerator: perms.isModerator, isContributor: perms.isContributor,
      canManage: perms.canManage, canSubmit: perms.canSubmit, characterName: perms.characterName
    });
  }

  // ---- facility log ----
  if (url.pathname === '/api/log' && request.method === 'GET') {
    const perms = await getPermissions(request, env);
    const entries = await getLogEntries(env);
    if (perms.canManage) return json(entries);
    return json(entries.filter(e => e.approved).map(e => ({ id: e.id, date: e.date, status: e.status, title: e.title, body: e.body })));
  }

  if (url.pathname === '/api/log' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.canSubmit) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body) return json({ ok: false, error: 'Invalid request.' }, 400);
    const date = (body.date || '').toString().trim();
    const status = (body.status || '').toString().trim();
    const title = (body.title || '').toString().trim();
    const entryBody = (body.body || '').toString().trim();
    if (!date || !status || !title || !entryBody) return json({ ok: false, error: 'All fields are required.' }, 400);
    const entries = await getLogEntries(env);
    entries.unshift({
      id: crypto.randomUUID(),
      date, status, title, body: entryBody,
      approved: perms.canManage,
      authorId: perms.discordId,
      authorName: perms.characterName || perms.username
    });
    await saveLogEntries(env, entries);
    return json({ ok: true });
  }

  if (url.pathname === '/api/log/edit' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body || !body.id) return json({ ok: false, error: 'Invalid request.' }, 400);
    const entries = await getLogEntries(env);
    const entry = entries.find(e => e.id === body.id);
    if (!entry) return json({ ok: false, error: 'Entry not found.' }, 404);
    entry.date = (body.date || entry.date).toString().trim();
    entry.status = (body.status || entry.status).toString().trim();
    entry.title = (body.title || entry.title).toString().trim();
    entry.body = (body.body || entry.body).toString().trim();
    await saveLogEntries(env, entries);
    return json({ ok: true });
  }

  if (url.pathname === '/api/log/approve' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body || !body.id) return json({ ok: false, error: 'Invalid request.' }, 400);
    const entries = await getLogEntries(env);
    const entry = entries.find(e => e.id === body.id);
    if (!entry) return json({ ok: false, error: 'Entry not found.' }, 404);
    entry.approved = true;
    await saveLogEntries(env, entries);
    return json({ ok: true });
  }

  if (url.pathname === '/api/log/delete' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body || !body.id) return json({ ok: false, error: 'Invalid request.' }, 400);
    const entries = await getLogEntries(env);
    const next = entries.filter(e => e.id !== body.id);
    await saveLogEntries(env, next);
    return json({ ok: true });
  }

  // ---- accounts (God + Moderator) ----
  if (url.pathname === '/api/users' && request.method === 'GET') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    return json(await listUsers(env));
  }

  if (url.pathname === '/api/users/block' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body || !body.discordId) return json({ ok: false, error: 'Invalid request.' }, 400);
    if (body.discordId === OWNER_DISCORD_ID) return json({ ok: false, error: 'Cannot block the God account.' }, 400);
    const record = await getUserRecord(env, body.discordId);
    if (!record) return json({ ok: false, error: 'Account not found.' }, 404);
    if (!canActOnTarget(perms, record)) return json({ ok: false, error: 'Not authorized.' }, 403);
    record.blocked = !!body.blocked;
    await env.HARDTIMES_USERS.put(USER_KEY_PREFIX + body.discordId, JSON.stringify(record));
    return json({ ok: true });
  }

  if (url.pathname === '/api/users/remove' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body || !body.discordId) return json({ ok: false, error: 'Invalid request.' }, 400);
    if (body.discordId === OWNER_DISCORD_ID) return json({ ok: false, error: 'Cannot remove the God account.' }, 400);
    const record = await getUserRecord(env, body.discordId);
    if (!record) return json({ ok: false, error: 'Account not found.' }, 404);
    if (!canActOnTarget(perms, record)) return json({ ok: false, error: 'Not authorized.' }, 403);
    await env.HARDTIMES_USERS.delete(USER_KEY_PREFIX + body.discordId);
    return json({ ok: true });
  }

  if (url.pathname === '/api/users/assign-character' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body || !body.discordId) return json({ ok: false, error: 'Invalid request.' }, 400);
    const record = await getUserRecord(env, body.discordId);
    if (!record) return json({ ok: false, error: 'Account not found.' }, 404);
    if (!canActOnTarget(perms, record)) return json({ ok: false, error: 'Not authorized.' }, 403);
    const slug = (body.characterSlug || '').toString().trim();
    if (!slug) {
      record.characterSlug = null;
      record.characterName = null;
    } else {
      const character = CHARACTERS.find(c => c.slug === slug);
      if (!character) return json({ ok: false, error: 'Unknown character.' }, 400);
      record.characterSlug = character.slug;
      record.characterName = character.name;
    }
    await env.HARDTIMES_USERS.put(USER_KEY_PREFIX + body.discordId, JSON.stringify(record));
    return json({ ok: true });
  }

  if (url.pathname === '/api/users/set-moderator' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.isGod) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body || !body.discordId) return json({ ok: false, error: 'Invalid request.' }, 400);
    if (body.discordId === OWNER_DISCORD_ID) return json({ ok: false, error: 'Cannot change the God account.' }, 400);
    const record = await getUserRecord(env, body.discordId);
    if (!record) return json({ ok: false, error: 'Account not found.' }, 404);
    record.isModerator = !!body.isModerator;
    await env.HARDTIMES_USERS.put(USER_KEY_PREFIX + body.discordId, JSON.stringify(record));
    return json({ ok: true });
  }

  if (url.pathname === '/api/users/revoke-sessions' && request.method === 'POST') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    const body = await readJson(request);
    if (!body || !body.discordId) return json({ ok: false, error: 'Invalid request.' }, 400);
    const record = await getUserRecord(env, body.discordId);
    if (!record) return json({ ok: false, error: 'Account not found.' }, 404);
    if (!canActOnTarget(perms, record)) return json({ ok: false, error: 'Not authorized.' }, 403);
    record.sessionEpoch = (record.sessionEpoch || 0) + 1;
    await env.HARDTIMES_USERS.put(USER_KEY_PREFIX + body.discordId, JSON.stringify(record));
    return json({ ok: true });
  }

  // ---- login audit trail (God + Moderator) ----
  if (url.pathname === '/api/audit' && request.method === 'GET') {
    const perms = await getPermissions(request, env);
    if (!perms.canManage) return json({ ok: false, error: 'Not authorized.' }, 403);
    return json(await getAudit(env));
  }

  // ---- Discord OAuth ----
  if (url.pathname === '/warden' && request.method === 'GET') {
    const existing = await getPermissions(request, env);
    if (existing.loggedIn) {
      return Response.redirect(SITE_URL, 302);
    }
    const state = crypto.randomUUID();
    const authorizeUrl = new URL('https://discord.com/api/oauth2/authorize');
    authorizeUrl.searchParams.set('client_id', DISCORD_CLIENT_ID);
    authorizeUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('scope', 'identify guilds.members.read');
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
      const headers = new Headers(htmlHeaders);
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
      const headers = new Headers(htmlHeaders);
      headers.append('Set-Cookie', clearState);
      return new Response(errorPage('Login Failed', 'Discord rejected that login attempt.'), { status: 401, headers });
    }
    const { access_token } = await tokenRes.json();

    const userRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` }
    });
    const user = await userRes.json();
    const isGod = user.id === OWNER_DISCORD_ID;

    const existingRecord = await getUserRecord(env, user.id);
    if (existingRecord && existingRecord.blocked) {
      await appendAudit(env, { time: Date.now(), discordId: user.id, username: user.username, role: existingRecord.role, result: 'blocked' });
      const headers = new Headers(htmlHeaders);
      headers.append('Set-Cookie', clearState);
      return new Response(errorPage('Access Denied', 'This account has been blocked from the Warden console.'), { status: 403, headers });
    }

    let record;
    if (isGod) {
      record = await upsertUserRecord(env, { discordId: user.id, username: user.username, role: 'god' });
    } else {
      const memberRes = await fetch(`https://discord.com/api/v10/users/@me/guilds/${GUILD_ID}/member`, {
        headers: { Authorization: `Bearer ${access_token}` }
      });
      if (!memberRes.ok) {
        const headers = new Headers(htmlHeaders);
        headers.append('Set-Cookie', clearState);
        return new Response(errorPage('Not a Member', 'You must be a member of the required Discord server to log in.'), { status: 403, headers });
      }
      const member = await memberRes.json();
      const roles = member.roles || [];
      const derivedRole = roles.includes(CONTRIBUTOR_ROLE_ID) ? 'contributor' : 'member';
      record = await upsertUserRecord(env, { discordId: user.id, username: user.username, role: derivedRole });
    }

    await appendAudit(env, { time: Date.now(), discordId: user.id, username: user.username, role: record.role, result: 'success' });

    const exp = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
    const authSecret = await env.AUTH_SECRET.get();
    const token = await signToken({ id: user.id, username: user.username, epoch: record.sessionEpoch || 0, exp }, authSecret);
    const headers = new Headers({ Location: SITE_URL, 'Cache-Control': 'no-store, private' });
    headers.append('Set-Cookie', `${COOKIE_NAME}=${token}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`);
    headers.append('Set-Cookie', clearState);
    return new Response(null, { status: 302, headers });
  }

  if (url.pathname === '/warden/logout') {
    const headers = new Headers({ Location: SITE_URL, 'Cache-Control': 'no-store, private' });
    headers.append('Set-Cookie', `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
    return new Response(null, { status: 302, headers });
  }

  return env.ASSETS.fetch(request);
}

export default {
  async fetch(request, env, ctx) {
    return withSecurityHeaders(await handleRequest(request, env, ctx));
  }
};
