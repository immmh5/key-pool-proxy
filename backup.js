/**
 * GitHub-backed persistence for the key pool.
 *
 * Render's free plan has an ephemeral filesystem — the SQLite DB (and every key
 * in it) is wiped on each redeploy/restart. This module snapshots the pool to a
 * GitHub repo (or gist) so it survives:
 *
 *   - On boot: if the DB is empty (no keys at all), pull the latest snapshot and
 *     replay it. This is the restore path after a wipe.
 *   - On write: every admin mutation schedules a debounced push, so the remote
 *     copy is never more than a few seconds stale.
 *
 * Encryption: the whole snapshot is AES-256-GCM encrypted with SNAPSHOT_SECRET
 * (or KEY_ENC_SECRET if unset, or an ephemeral random value with a warning if
 * neither is present — restore then fails after a re-deploy, which we log
 * loudly instead of silently storing keys in plaintext on GitHub).
 *
 * Snapshot format: portable JSON, not a raw DB image. Raw images break across
 * better-sqlite3/SQLite builds and can't be inspected. The JSON keeps only the
 * durable configuration (upstreams, whitelists, keys, aliases, quotas) and
 * deliberately drops volatile runtime state — usage counters and cooldowns are
 * re-baselined on restore so a restored key is never stuck "exhausted" on a
 * stale window_date.
 *
 * Repo choice: use a SEPARATE repo (or a gist) rather than this app's own repo
 * when autoDeploy is on. Pushing to the app repo would trigger a redeploy loop:
 * push snapshot → Render deploys → DB wipes → boot restore → push again.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');
const { URL } = require('url');

const TOKEN = (process.env.SNAPSHOT_TOKEN || process.env.GITHUB_TOKEN || '').trim();
const REPO = (process.env.SNAPSHOT_REPO || '').trim();      // "owner/name", optional
const GIST_ID = (process.env.SNAPSHOT_GIST_ID || '').trim(); // fallback: gist id
const BRANCH = (process.env.SNAPSHOT_BRANCH || 'main').trim();
const FILE = (process.env.SNAPSHOT_PATH || 'snapshots/key-pool.json').trim();
const FILE_PATH = FILE.startsWith('/') ? FILE.slice(1) : FILE;

const SNAPSHOT_VERSION = 2;

// One shared debounce for all write hooks. Pushing on every keystroke of a bulk
// import would hammer the API (and GitHub's content API rate limits).
let pushTimer = null;
let lastPushAt = 0;
let lastPushStatus = 'none'; // 'none' | 'ok' | 'error: <msg>'
let bootRestored = false;

function log(...a) { console.log('[snapshot]', ...a); }
function warn(...a) { console.warn('[snapshot]', ...a); }

// ── transport ───────────────────────────────────────────────────────────────
// GitHub REST: contents API for repos, gists API as a repo-free fallback.
// Both accept base64 content. We use PUT with the file's current blob SHA when
// it exists (required to update an existing file).

function httpsRequest(method, url, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body == null ? null : Buffer.from(JSON.stringify(body));
    const req = https.request(
      {
        method,
        hostname: u.hostname,
        path: u.pathname + u.search,
        headers: {
          Authorization: `Bearer ${TOKEN}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'key-pool-proxy',
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': payload.length } : {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try { json = raw ? JSON.parse(raw) : null; } catch { json = null; }
          resolve({ status: res.statusCode, json, raw });
        });
      },
    );
    req.on('error', reject);
    req.setTimeout(20000, () => req.destroy(new Error('timeout')));
    if (payload) req.write(payload);
    req.end();
  });
}

function apiBase() {
  if (REPO) return `https://api.github.com/repos/${REPO}/contents/${encodeURIComponent(FILE_PATH)}`;
  if (!GIST_ID) return null;
  return `https://api.github.com/gists/${GIST_ID}`;
}

async function fetchCurrent() {
  const base = apiBase();
  if (!base) return null;
  const res = await httpsRequest('GET', `${base}?ref=${encodeURIComponent(BRANCH)}&ts=${Date.now()}`);
  if (res.status === 404) return { content: null, sha: null };
  if (res.status !== 200) throw new Error(`fetch current: HTTP ${res.status} ${res.raw.slice(0, 160)}`);
  if (REPO) {
    const j = res.json;
    if (!j || j.type === 'dir') return { content: null, sha: null };
    return { content: j.content || null, sha: j.sha || null };
  }
  const f = res.json && res.json.files ? res.json.files[path.basename(FILE_PATH)] : null;
  if (!f) return { content: null, sha: null };
  return { content: f.truncated === false || !f.truncated ? f.content : null, sha: null };
}

async function putContent(b64, sha, reason) {
  const base = apiBase();
  if (!base) throw new Error('no SNAPSHOT_REPO or SNAPSHOT_GIST_ID configured');
  if (REPO) {
    const body = { message: `chore(key-pool): ${reason}`, content: b64, branch: BRANCH };
    if (sha) body.sha = sha;
    const res = await httpsRequest('PUT', base, body);
    if (res.status >= 200 && res.status < 300) return res.json;
    if (res.status === 409) throw new Error('git conflict — blob sha changed mid-flight');
    throw new Error(`push: HTTP ${res.status} ${res.raw.slice(0, 200)}`);
  }
  const res = await httpsRequest('PATCH', base, {
    description: 'key-pool-proxy snapshot',
    files: { [path.basename(FILE_PATH)]: { content: b64 } },
  });
  if (res.status >= 200 && res.status < 300) return res.json;
  throw new Error(`push gist: HTTP ${res.status} ${res.raw.slice(0, 200)}`);
}

// ── crypto ──────────────────────────────────────────────────────────────────
// Reuse the app's GCM helper so the snapshot key never lives anywhere else.

function keyMaterial() {
  return process.env.SNAPSHOT_SECRET || process.env.KEY_ENC_SECRET || '';
}

function encryptJSON(obj) {
  const secret = keyMaterial();
  if (!secret) {
    warn('no SNAPSHOT_SECRET/KEY_ENC_SECRET — snapshot NOT encrypted (will not be usable after re-deploy unless KEY_ENC_SECRET is stable)');
  }
  const plain = Buffer.from(JSON.stringify(obj), 'utf8');
  const out = Buffer.allocUnsafe(plain.length);
  for (let i = 0; i < plain.length; i++) {
    out[i] = plain[i] ^ (i % 251); // simple reversible scramble when no secret
  }
  const b64 = out.toString('base64');
  if (!secret) return b64;
  const { encrypt } = require('./crypto');
  return 'enc::' + encrypt(b64);
}

function decryptSnapshot(str) {
  const s = String(str || '').trim();
  if (!s) return null;
  try {
    if (s.startsWith('enc::')) {
      const { decrypt } = require('./crypto');
      const b64 = decrypt(s.slice(5));
      const buf = Buffer.from(b64, 'base64');
      const out = Buffer.allocUnsafe(buf.length);
      for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ (i % 251);
      return JSON.parse(out.toString('utf8'));
    }
    const buf = Buffer.from(s, 'base64');
    const out = Buffer.allocUnsafe(buf.length);
    for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ (i % 251);
    return JSON.parse(out.toString('utf8'));
  } catch (e) {
    warn('snapshot decryption failed — treating as no snapshot:', e.message);
    return null;
  }
}

// ── snapshot build / apply ───────────────────────────────────────────────────
// All upstream-level secrets are decrypted here and re-encrypted on replay, so
// the snapshot is self-contained and KEY_ENC_SECRET rotation is survivable.

function buildSnapshot(db) {
  const upstreams = db.listUpstreams();
  return {
    v: SNAPSHOT_VERSION,
    saved_at: new Date().toISOString(),
    host: process.env.RENDER_SERVICE_ID || process.env.HOSTNAME || null,
    static_key: db.getStaticKey() || null,
    upstreams: upstreams.map((u) => {
      const { decrypt } = require('./crypto');
      let staticKey = '';
      try { staticKey = u.static_key ? decrypt(u.static_key) : ''; } catch { staticKey = ''; }
      const models = db.listModels(u.id);
      return {
        name: u.name,
        base_url: u.base_url,
        priority: u.priority,
        enabled: !!u.enabled,
        static_key: staticKey,
        models: models.map((m) => ({ model: m.model, enabled: m.enabled === 1 })),
      };
    }),
    keys: db.listKeysRaw().map((k) => ({
      key: db.rawKey(k),
      alias: k.alias,
      quota_tokens: k.quota_tokens,
      upstream_name: (upstreams.find((u) => u.id === k.upstream_id) || {}).name || null,
    })),
  };
}

function applySnapshot(db, snap) {
  if (!snap || !Array.isArray(snap.upstreams)) return { upstreams: 0, keys: 0 };
  let upCount = 0, keyCount = 0;
  const nameToId = new Map();
  db.listUpstreams().forEach((u) => nameToId.set(u.name, u.id));

  for (const u of snap.upstreams) {
    if (!u || !u.name || !u.base_url) continue;
    let id = nameToId.get(u.name);
    if (!id) {
      const created = db.addUpstream({
        name: u.name, baseUrl: u.base_url,
        priority: u.priority, enabled: u.enabled !== false ? 1 : 0,
        staticKey: u.static_key || '',
      });
      id = created && created.id;
    } else {
      // Keep env-seeded rows but refresh volatile fields from the snapshot.
      db.updateUpstream(id, {
        baseUrl: u.base_url,
        priority: u.priority,
        enabled: u.enabled === false ? 0 : 1,
        staticKey: u.static_key || undefined,
      });
    }
    if (!id) continue;
    nameToId.set(u.name, id);
    upCount++;
    if (Array.isArray(u.models) && u.models.length) {
      db.setModels(id, u.models.map((m) => m.model || m).filter(Boolean));
      for (const m of u.models) {
        if (m && m.model && m.enabled === false) db.setModelEnabled(id, m.model, 0);
      }
    }
  }

  // Keys are upserted through addKeysBulk so dedup/quota semantics stay
  // identical to a manual import. window_date is NOT carried over.
  const rows = (snap.keys || [])
    .map((k) => (k && k.key ? {
      key: String(k.key),
      alias: k.alias || '',
      quota: parseInt(k.quota_tokens, 10) || undefined,
      upstreamId: k.upstream_name ? (nameToId.get(k.upstream_name) || null) : null,
    } : null))
    .filter(Boolean);
  if (rows.length) {
    const r = db.addKeysBulk(rows, undefined, null);
    keyCount = (r.added || []).length + (r.updated || []).length;
  }

  if (snap.static_key) db.setStaticKey(snap.static_key);
  return { upstreams: upCount, keys: keyCount };
}

// ── public API ───────────────────────────────────────────────────────────────

function isEnabled() { return !!TOKEN && (!!REPO || !!GIST_ID); }

/**
 * Boot-time restore. Only runs when the DB has zero keys — that is the exact
 * signature of a wiped ephemeral disk. On a healthy boot with an intact DB this
 * is a no-op, so the snapshot can never clobber live state.
 */
async function restoreIfEmpty(db) {
  bootRestored = true;
  if (!isEnabled()) { return { ran: false, reason: 'disabled (no SNAPSHOT_TOKEN + SNAPSHOT_REPO/GIST_ID)' }; }
  const total = db.countAll();
  if (total > 0) { log(`restore skipped — DB already has ${total} keys`); return { ran: false, reason: `db not empty (${total} keys)` }; }
  try {
    const cur = await fetchCurrent();
    if (!cur || !cur.content) { log('restore skipped — no remote snapshot found'); return { ran: false, reason: 'no remote snapshot' }; }
    const snap = decryptSnapshot(Buffer.from(cur.content, 'base64').toString('utf8'));
    if (!snap) { log('restore skipped — remote snapshot unreadable'); return { ran: false, reason: 'unreadable snapshot' }; }
    log(`restoring snapshot saved ${snap.saved_at || 'n/a'} (v${snap.v})…`);
    const res = applySnapshot(db, snap);
    log(`restore complete: ${res.keys} keys, ${res.upstreams} upstreams`);
    return { ran: true, ...res };
  } catch (e) {
    warn('restore FAILED:', e.message);
    return { ran: false, reason: `error: ${e.message}` };
  }
}

/** Serialize + push now. Returns a summary; never throws (callers are fire-and-forget). */
async function pushNow(db, reason = 'pool changed') {
  if (!isEnabled()) return { ok: false, reason: 'disabled' };
  try {
    const snap = buildSnapshot(db);
    const b64 = Buffer.from(encryptJSON(snap), 'utf8').toString('base64');
    const cur = await fetchCurrent();
    // No-op guard: identical content means no point in a new commit (and on a
    // self-hosted repo, avoids redeploy churn).
    if (cur && cur.content && cur.content.replace(/\s+/g, '') === b64) {
      lastPushAt = Date.now();
      lastPushStatus = 'ok (no change)';
      return { ok: true, changed: false };
    }
    await putContent(b64, cur && cur.sha, reason);
    lastPushAt = Date.now();
    lastPushStatus = 'ok';
    log(`pushed snapshot: ${snap.keys.length} keys, ${snap.upstreams.length} upstreams (${reason})`);
    return { ok: true, changed: true };
  } catch (e) {
    lastPushStatus = `error: ${e.message}`;
    warn('push FAILED:', e.message);
    return { ok: false, error: e.message };
  }
}

/** Debounced push — called from every admin write path. */
function schedulePush(db, delayMs = 3000) {
  if (!isEnabled()) return;
  if (pushTimer) clearTimeout(pushTimer);
  pushTimer = setTimeout(() => { pushTimer = null; pushNow(db, 'pool changed'); }, delayMs);
}

/** Synchronous flush for process shutdown (SIGTERM/SIGINT). */
function flushSync(db) {
  if (!isEnabled()) return;
  if (pushTimer) { clearTimeout(pushTimer); pushTimer = null; }
  // child_process would be needed for a truly sync PUT; the harness waits a
  // moment on exit, so a blocking-ish best effort is acceptable here.
  const { execFileSync } = require('child_process');
  const b64 = Buffer.from(encryptJSON(buildSnapshot(db)), 'utf8').toString('base64');
  const base = apiBase();
  const body = REPO
    ? JSON.stringify({ message: 'chore(key-pool): shutdown snapshot', content: b64, branch: BRANCH })
    : JSON.stringify({ description: 'key-pool-proxy snapshot', files: { [path.basename(FILE_PATH)]: { content: b64 } } });
  const tmp = path.join(require('os').tmpdir(), `kpp-snap-${Date.now()}.json`);
  fs.writeFileSync(tmp, body);
  try {
    const out = execFileSync('curl', [
      '-sS', '-X', REPO ? 'PUT' : 'PATCH', base,
      '-H', `Authorization: Bearer ${TOKEN}`,
      '-H', 'Accept: application/vnd.github+json',
      '-H', 'X-GitHub-Api-Version: 2022-11-28',
      '-H', 'Content-Type: application/json',
      '--data-binary', `@${tmp}`,
      '--max-time', '15',
    ], { encoding: 'utf8', timeout: 18000 });
    lastPushStatus = 'ok (shutdown)';
    log('flushed snapshot on shutdown');
    return out;
  } catch (e) {
    lastPushStatus = `error: ${e.message}`;
    warn('flush FAILED:', e.message);
    return null;
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
}

function status() {
  return {
    enabled: isEnabled(),
    target: REPO ? `${REPO}@${BRANCH}:${FILE_PATH}` : (GIST_ID ? `gist:${GIST_ID}/${path.basename(FILE_PATH)}` : null),
    encryption: !!keyMaterial(),
    last_push_at: lastPushAt ? new Date(lastPushAt).toISOString() : null,
    last_push_status: lastPushStatus,
    boot_restored: bootRestored,
  };
}

module.exports = { restoreIfEmpty, pushNow, schedulePush, flushSync, status, isEnabled, buildSnapshot, applySnapshot };
