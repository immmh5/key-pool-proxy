'use strict';
/**
 * Key Pool data layer — SQLite via better-sqlite3.
 *
 * Why better-sqlite3? It is *synchronous*, so every read-then-write sequence
 * (pick key → account usage) executes atomically inside the single Node
 * event loop. Combined with a WAL journal file, this removes the classic
 * race conditions that plague async DB drivers in key-pool proxies.
 */
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const kc = require('./crypto');

// ── config (env with sane defaults) ──────────────────────────────
const DEFAULT_QUOTA = parseInt(process.env.DEFAULT_KEY_QUOTA || '1000000', 10); // tokens / 24h per key
const FAIL_THRESHOLD = parseInt(process.env.FAIL_THRESHOLD || '5', 10);          // consecutive failures → cooldown
const COOLDOWN_MS = parseInt(process.env.COOLDOWN_MS || String(10 * 60 * 1000), 10); // 10 min
const DB_PATH = process.env.DB_PATH || './data/key-pool.db';

let db = null;

function today() {
  // Window date in UTC — change TZ if you need local midnight.
  return new Date().toISOString().slice(0, 10);
}

function nowMs() {
  return Date.now();
}

function seedFromEnv() {
  // Build the seed list: legacy UPSTREAM_BASE_URL first, then a multi-upstream
  // UPSTREAMS JSON array (which wins on name collisions). The ephemeral free-plan
  // filesystem wipes the DB on every redeploy, so env seeding is the only way to
  // keep the upstream set reproducible across deploys.
  const byName = new Map();
  const legacy = (process.env.UPSTREAM_BASE_URL || '').trim().replace(/\/+$/, '');
  if (legacy) byName.set('default', { name: 'default', base_url: legacy, priority: 0, models: null, static_key: process.env.STATIC_UPSTREAM_KEY || '' });

  const raw = (process.env.UPSTREAMS || '').trim();
  if (raw) {
    let arr = null;
    try { arr = JSON.parse(raw); } catch { arr = null; }
    if (Array.isArray(arr)) {
      for (const u of arr) {
        const baseUrl = (u.base_url || u.baseUrl || '').trim().replace(/\/+$/, '');
        if (!u || !baseUrl || !u.name) continue;
        byName.set(String(u.name), {
          name: String(u.name),
          base_url: baseUrl,
          priority: parseInt(u.priority, 10) || 0,
          models: Array.isArray(u.models) ? u.models.map((m) => String(m)) : null,
          static_key: u.static_key || u.api_key || '',
        });
      }
    }
  }
  if (!byName.size) return null;

  for (const u of [...byName.values()].sort((a, b) => a.priority - b.priority)) {
    const ex = db.prepare('SELECT id FROM upstreams WHERE name = ?').get(u.name);
    if (ex) continue;
    const info = db.prepare(`
      INSERT INTO upstreams (name, base_url, priority, static_key)
      VALUES (?, ?, ?, ?)
    `).run(u.name, u.base_url, u.priority, u.static_key ? kc.encrypt(u.static_key) : '');
    if (u.models && u.models.length) {
      const ins = db.prepare('INSERT OR IGNORE INTO upstream_models (upstream_id, model, enabled) VALUES (?, ?, 1)');
      const txn = db.transaction((ms) => ms.forEach((m) => ins.run(info.lastInsertRowid, m)));
      txn(u.models);
    }
  }
  return db.prepare('SELECT * FROM upstreams ORDER BY priority ASC, id ASC').all();
}

function init(overridePath) {
  if (db) return db;
  const dbPath = overridePath || DB_PATH;
  if (dbPath !== ':memory:') require('fs').mkdirSync(path.dirname(dbPath), { recursive: true });
  db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  db.pragma('synchronous = NORMAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS keys (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      key               TEXT NOT NULL UNIQUE,
      key_sha           TEXT NOT NULL UNIQUE,   -- sha256 of PLAINTEXT (dedup + lookup)
      alias            TEXT NOT NULL DEFAULT '',
      quota_tokens      INTEGER NOT NULL DEFAULT ${DEFAULT_QUOTA},
      used_tokens       INTEGER NOT NULL DEFAULT 0,
      window_date       TEXT    NOT NULL DEFAULT '',
      status            TEXT    NOT NULL DEFAULT 'active',  -- active | exhausted | cooldown | disabled | no_quota
      cooldown_until    INTEGER NOT NULL DEFAULT 0,
      fail_count        INTEGER NOT NULL DEFAULT 0,
      last_used_at      TEXT,
      last_code         INTEGER,
      last_error        TEXT,
      upstream_id       INTEGER,                 -- which upstream this key serves (NULL = legacy default)
      created_at        TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_keys_sel ON keys(status, window_date, used_tokens);
    CREATE INDEX IF NOT EXISTS idx_keys_upstream ON keys(upstream_id, status, used_tokens);
    CREATE TABLE IF NOT EXISTS meta (
      k TEXT PRIMARY KEY,
      v TEXT
    );
    CREATE TABLE IF NOT EXISTS upstreams (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT NOT NULL UNIQUE,          -- url-safe slug, used in /v1/<name>/...
      base_url    TEXT NOT NULL,
      enabled     INTEGER NOT NULL DEFAULT 1,
      priority    INTEGER NOT NULL DEFAULT 0,    -- lower = tried first on failover
      static_key  TEXT NOT NULL DEFAULT '',      -- AES-encrypted; '' = rotate the pool instead
      created_at  TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS upstream_models (
      upstream_id INTEGER NOT NULL,
      model       TEXT NOT NULL,
      enabled     INTEGER NOT NULL DEFAULT 1,    -- 0 = hidden from /v1/models and excluded from routing
      PRIMARY KEY (upstream_id, model)
    );
  `);

  // Migrate pre-multi-upstream databases: existing keys belong to the default upstream.
  const seeded = seedFromEnv();
  const def = db.prepare("SELECT id FROM upstreams WHERE name = 'default'").get();
  if (def) db.prepare('UPDATE keys SET upstream_id = ? WHERE upstream_id IS NULL').run(def.id);

  // Migrate the legacy global static token onto the default upstream.
  const legacyStatic = db.prepare("SELECT v FROM meta WHERE k = 'static_key'").get();
  if (legacyStatic && legacyStatic.v && def) {
    const cur = db.prepare('SELECT static_key FROM upstreams WHERE id = ?').get(def.id);
    if (cur && !cur.static_key) {
      db.prepare('UPDATE upstreams SET static_key = ? WHERE id = ?').run(legacyStatic.v, def.id);
    }
    db.prepare("DELETE FROM meta WHERE k = 'static_key'").run();
  }
  return db;
}

function sha256(plain) { return crypto.createHash('sha256').update(String(plain)).digest('hex'); }

function maskKey(plain) {
  const s = String(plain || '');
  if (s.length <= 8) return s;
  return s.slice(0, 4) + '…' + s.slice(-4);
}

/** Shape a DB row for JSON responses — mask + decrypt-on-demand markers. */
function toPublic(row) {
  if (!row) return null;
  const plain = kc.decrypt(row.key);
  return {
    id: row.id,
    key: maskKey(plain),            // masked, safe to show in the UI
    key_sha: row.key_sha.slice(0, 12) + '…',
    alias: row.alias,
    upstream_id: row.upstream_id,
    quota_tokens: row.quota_tokens,
    used_tokens: row.used_tokens,
    remaining: Math.max(0, row.quota_tokens - row.used_tokens),
    percent: row.quota_tokens > 0 ? Math.round((row.used_tokens / row.quota_tokens) * 10000) / 100 : 0,
    window_date: row.window_date,
    status: row.status,
    cooldown_until: row.cooldown_until,
    fail_count: row.fail_count,
    last_used_at: row.last_used_at,
    last_code: row.last_code,
    last_error: row.last_error,
    created_at: row.created_at,
  };
}

// ── add one key (upsert by plaintext hash: re-import bumps quota/alias) ──
function addKey({ key, alias = '', quota = DEFAULT_QUOTA, upstreamId = null }) {
  key = String(key || '').trim();
  if (!key) return null;
  const sha = sha256(key);
  const stored = kc.encrypt(key);
  const existing = db.prepare('SELECT id FROM keys WHERE key_sha = ?').get(sha);
  const now = new Date().toISOString();
  if (existing) {
    db.prepare(`
      UPDATE keys
         SET alias = CASE WHEN ? = '' THEN alias ELSE ? END,
             quota_tokens = ?,
             used_tokens = CASE WHEN window_date <> ? THEN 0 ELSE used_tokens END,
             window_date = ?,
             last_used_at = ?,
             upstream_id = COALESCE(?, upstream_id)
       WHERE id = ?
    `).run(alias, alias, quota, today(), today(), now, upstreamId, existing.id);
    return db.prepare('SELECT * FROM keys WHERE id = ?').get(existing.id);
  }
  const info = db.prepare(`
    INSERT INTO keys (key, key_sha, alias, quota_tokens, window_date, upstream_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(stored, sha, alias, quota, today(), upstreamId, now);
  return db.prepare('SELECT * FROM keys WHERE id = ?').get(info.lastInsertRowid);
}

/** Bulk add — one transaction. Returns {added, updated}. */
function addKeysBulk(list, defaultQuota = DEFAULT_QUOTA, upstreamId = null) {
  const added = [], updated = [];
  const txn = db.transaction((rows) => {
    for (const r of rows) {
      const key = String(r.key || '').trim();
      if (!key) continue;
      const ex = db.prepare('SELECT id FROM keys WHERE key_sha = ?').get(sha256(key));
      const row = addKey({ key, alias: r.alias || '', quota: parseInt(r.quota, 10) || defaultQuota, upstreamId });
      if (!row) continue;
      (ex ? updated : added).push(row.id);
    }
  });
  txn(list);
  return { added, updated };
}

// ── upstream registry ───────────────────────────────────────────────
// A row here is one OpenAI-compatible backend. `name` is the url-safe slug used
// for explicit routing (`/v1/<name>/chat/completions`), `priority` controls the
// failover order across upstreams that all serve the same model, and `static_key`
// is an optional never-rotate token (the "key per upstream" mode).
function listUpstreams() {
  return db.prepare(`
    SELECT u.*,
           (SELECT COUNT(*) FROM keys k WHERE k.upstream_id = u.id) AS key_count,
           (SELECT COUNT(*) FROM upstream_models m WHERE m.upstream_id = u.id AND m.enabled = 1) AS model_count
      FROM upstreams u
     ORDER BY u.priority ASC, u.id ASC
  `).all();
}

function getUpstream(id) {
  return db.prepare('SELECT * FROM upstreams WHERE id = ?').get(id);
}

function getUpstreamByName(name) {
  return db.prepare('SELECT * FROM upstreams WHERE name = ?').get(name);
}

function addUpstream({ name, baseUrl, priority = 0, enabled = 1, staticKey = '' }) {
  name = String(name || '').trim();
  baseUrl = String(baseUrl || '').trim().replace(/\/+$/, '');
  if (!name || !baseUrl) return null;
  const info = db.prepare(`
    INSERT INTO upstreams (name, base_url, priority, enabled, static_key)
    VALUES (?, ?, ?, ?, ?)
  `).run(name, baseUrl, parseInt(priority, 10) || 0, enabled ? 1 : 0, staticKey ? kc.encrypt(staticKey) : '');
  return getUpstream(info.lastInsertRowid);
}

function updateUpstream(id, { name, baseUrl, priority, enabled, staticKey }) {
  const cur = getUpstream(id);
  if (!cur) return null;
  const patch = {
    name: name !== undefined ? String(name).trim() : cur.name,
    base_url: baseUrl !== undefined ? String(baseUrl).trim().replace(/\/+$/, '') : cur.base_url,
    priority: priority !== undefined ? (parseInt(priority, 10) || 0) : cur.priority,
    enabled: enabled !== undefined ? (enabled ? 1 : 0) : cur.enabled,
    static_key: staticKey !== undefined ? (staticKey ? kc.encrypt(staticKey) : '') : cur.static_key,
  };
  db.prepare(`
    UPDATE upstreams
       SET name = ?, base_url = ?, priority = ?, enabled = ?, static_key = ?
     WHERE id = ?
  `).run(patch.name, patch.base_url, patch.priority, patch.enabled, patch.static_key, id);
  return getUpstream(id);
}

function deleteUpstream(id) {
  const cur = getUpstream(id);
  if (!cur) return false;
  const txn = db.transaction(() => {
    db.prepare('DELETE FROM upstream_models WHERE upstream_id = ?').run(id);
    db.prepare('DELETE FROM keys WHERE upstream_id = ?').run(id);
    db.prepare('DELETE FROM upstreams WHERE id = ?').run(id);
  });
  txn();
  return true;
}

function setUpstreamStaticKey(id, plain) {
  const cur = getUpstream(id);
  if (!cur) return null;
  db.prepare('UPDATE upstreams SET static_key = ? WHERE id = ?')
    .run(plain ? kc.encrypt(plain) : '', id);
  return getUpstream(id);
}

// ── model whitelist per upstream ────────────────────────────────────
// `enabled` decides whether /v1/models advertises the model and whether
// model-based routing may land on this upstream for it.
function listModels(upstreamId, onlyEnabled = false) {
  return db.prepare(`
    SELECT model, enabled FROM upstream_models
     WHERE upstream_id = ?
       ${onlyEnabled ? 'AND enabled = 1' : ''}
     ORDER BY model ASC
  `).all(upstreamId);
}

function setModels(upstreamId, models) {
  const list = (Array.isArray(models) ? models : String(models || '').split(/[\s,]+/))
    .map((m) => String(m || '').trim())
    .filter(Boolean);
  const txn = db.transaction(() => {
    db.prepare('DELETE FROM upstream_models WHERE upstream_id = ?').run(upstreamId);
    const ins = db.prepare('INSERT OR IGNORE INTO upstream_models (upstream_id, model, enabled) VALUES (?, ?, 1)');
    for (const m of list) ins.run(upstreamId, m);
  });
  txn();
  return listModels(upstreamId);
}

function setModelEnabled(upstreamId, model, enabled) {
  db.prepare(`
    INSERT INTO upstream_models (upstream_id, model, enabled)
    VALUES (?, ?, ?)
    ON CONFLICT(upstream_id, model) DO UPDATE SET enabled = excluded.enabled
  `).run(upstreamId, model, enabled ? 1 : 0);
  return db.prepare('SELECT * FROM upstream_models WHERE upstream_id = ? AND model = ?').get(upstreamId, model);
}

function getUpstreamsForModel(model) {
  // Candidate upstreams for model-based routing, in failover (priority) order.
  return db.prepare(`
    SELECT u.* FROM upstreams u
    JOIN upstream_models m ON m.upstream_id = u.id
     WHERE u.enabled = 1
       AND m.enabled = 1
       AND m.model = ?
     ORDER BY u.priority ASC, u.id ASC
  `).all(model);
}

function listAllEnabledModels() {
  // The union advertised at GET /v1/models, with the upstreams that serve each.
  return db.prepare(`
    SELECT m.model AS id,
           (SELECT group_concat(u2.name, ',') FROM upstreams u2
             JOIN upstream_models mm ON mm.upstream_id = u2.id
             WHERE mm.model = m.model AND mm.enabled = 1 AND u2.enabled = 1) AS owners
      FROM upstream_models m
     WHERE m.enabled = 1
     GROUP BY m.model
     ORDER BY m.model ASC
  `).all();
}

// ── maintenance: resets counters for keys on a STALE window, revives cooldowns ──
// NOTE: intentional design — an 'exhausted'/'no_quota' key on the CURRENT window
// must NOT be resurrected here. Otherwise a just-exhausted key would be revived
// on the very next pick and rotation to the next key would never happen. It only
// resets once its window_date is stale (i.e. after a daily rollover) or a cooldown
// has elapsed.
function maintenance() {
  const t = today();
  db.prepare(`
    UPDATE keys
       SET used_tokens = 0, window_date = ?,
           status = CASE
             WHEN status = 'exhausted' THEN 'active'
             WHEN status = 'cooldown' AND cooldown_until <= ? THEN 'active'
             WHEN status = 'no_quota' THEN 'active'
             ELSE status
           END,
           fail_count = CASE WHEN cooldown_until <= ? THEN 0 ELSE fail_count END,
           cooldown_until = CASE WHEN cooldown_until <= ? THEN 0 ELSE cooldown_until END
     WHERE window_date <> ? OR (status = 'cooldown' AND cooldown_until <= ?)
  `).run(t, nowMs(), nowMs(), nowMs(), t, nowMs());
}

/** Emergency-return the real (decrypted) upstream key for a given row. */
function rawKey(row) {
  return kc.decrypt(row.key);
}

// ── rotation: reuse the active ("hottest") eligible key ─────────────
// Rotate only on exhaustion/failure: keep serving the key that already
// has quota consumed in this window (most-used-but-still-active) so a
// key is drained before moving on. A fully charged key is flipped to
// 'exhausted' by recordSuccess and drops out of the WHERE clause.
// Runs inside a synchronous transaction: the pick is atomic with any
// subsequent accounting that the request handler performs.
function pickKey(upstreamId) {
  const txn = db.transaction(() => {
    maintenance();
    const row = db.prepare(`
      SELECT * FROM keys
       WHERE status = 'active'
         AND used_tokens < quota_tokens
         AND cooldown_until <= ?
         AND (? IS NULL OR upstream_id = ?)
       ORDER BY used_tokens DESC, quota_tokens DESC, id ASC
       LIMIT 1
    `).get(nowMs(), upstreamId ?? null, upstreamId ?? null);
    return row || null;
  });
  return txn();
}

/** After a successful upstream call — move the used quota + mark exhausted when full. */
function recordSuccess(id, tokens) {
  db.transaction(() => {
    const row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
    if (!row) return;
    const t = today();
    const used = (row.window_date === t ? row.used_tokens : 0) + tokens;
    const status = used >= row.quota_tokens ? 'exhausted' : 'active';
    db.prepare(`
      UPDATE keys SET used_tokens = ?, window_date = ?, status = ?, fail_count = 0,
                      last_used_at = ?, last_code = 200, last_error = NULL
       WHERE id = ?
    `).run(used, t, status, new Date().toISOString(), id);
  })();
}

/** After an upstream failure — increment circuit breaker, cooldown after threshold. */
function recordFailure(id, code, error) {
  db.transaction(() => {
    const row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
    if (!row) return;
    const nextFail = row.fail_count + 1;
    const cooldown = code === 401 ? nowMs() + 12 * 60 * 60 * 1000 // auth — long cooldown
                  : nextFail >= FAIL_THRESHOLD ? nowMs() + COOLDOWN_MS : 0;
    const status = code === 401 && nextFail >= 2 ? 'disabled'
                 : nextFail >= FAIL_THRESHOLD ? 'cooldown'
                 : row.status;
    db.prepare(`
      UPDATE keys SET fail_count = ?, status = ?, cooldown_until = ?,
                      last_used_at = ?, last_code = ?, last_error = ?
       WHERE id = ?
    `).run(nextFail, status, cooldown, new Date().toISOString(), code, String(error).slice(0, 500), id);
  })();
}

/**
 * Record a response code WITHOUT tripping the circuit breaker — used for
 * client-caused 4xx (bad model, bad request) that are not the key's fault.
 */
function recordCode(id, code, error) {
  const row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  if (!row) return;
  db.prepare(`
    UPDATE keys SET last_used_at = ?, last_code = ?, last_error = ?
     WHERE id = ?
  `).run(new Date().toISOString(), code, String(error || '').slice(0, 500), id);
}

/** Issue a one-off quota top-up to a key (admin "recharge"). */
function topUp(id, tokens) {
  const row = db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
  if (!row) return null;
  db.prepare(`
    UPDATE keys SET quota_tokens = quota_tokens + ?, status = CASE WHEN ? > 0 THEN 'active' ELSE status END WHERE id = ?
  `).run(tokens, tokens, id);
  return db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
}

// ── admin helpers ──────────────────────────────────────────────────
function listKeysRaw({ upstreamId = null } = {}) {
  // Snapshot export needs the *raw* rows (still-encrypted key column), unlike
  // listKeys which masks. Do not expose over HTTP.
  const sql = 'SELECT * FROM keys';
  if (upstreamId == null) return db.prepare(sql).all();
  return db.prepare(`${sql} WHERE upstream_id = ?`).all(parseInt(upstreamId, 10));
}

function listKeys({ status, q, limit = 500, offset = 0, upstreamId = null } = {}) {
  let sql = 'SELECT * FROM keys WHERE 1=1';
  const args = [];
  if (status) { sql += ' AND status = ?'; args.push(status); }
  if (upstreamId) { sql += ' AND upstream_id = ?'; args.push(parseInt(upstreamId, 10)); }
  if (q) { sql += ' AND (alias LIKE ? OR key LIKE ?)'; args.push(`%${q}%`, `%${q}%`); }
  sql += ' ORDER BY status ASC, used_tokens DESC, id ASC LIMIT ? OFFSET ?';
  args.push(limit, offset);
  return db.prepare(sql).all(...args).map(toPublic);
}

function getRow(id) {
  return db.prepare('SELECT * FROM keys WHERE id = ?').get(id);
}

function updateKey(id, patch) {
  const row = getRow(id);
  if (!row) return null;
  const { status, alias, quota, upstream_id } = patch || {};
  db.prepare(`
    UPDATE keys SET
      status = COALESCE(?, status),
      alias = COALESCE(?, alias),
      quota_tokens = COALESCE(?, quota_tokens),
      upstream_id = CASE WHEN ? IS NULL THEN upstream_id ELSE ? END,
      cooldown_until = CASE WHEN ? = 'active' THEN 0 ELSE cooldown_until END,
      fail_count = CASE WHEN ? = 'active' THEN 0 ELSE fail_count END
     WHERE id = ?
  `).run(status ?? null, alias ?? null, quota ?? null, upstream_id ?? null, upstream_id ?? null, status ?? null, status ?? null, id);
  return getRow(id);
}

function deleteKey(id) {
  return db.prepare('DELETE FROM keys WHERE id = ?').run(id).changes > 0;
}

function resetUsage(id) {
  const info = db.prepare(`
    UPDATE keys SET used_tokens = 0, window_date = ?, status = 'active', fail_count = 0, cooldown_until = 0
     WHERE (? IS NULL OR id = ?)
  `).run(id ?? null, id ?? null);
  return info.changes;
}

function stats() {
  const t = today();
  const base = db.prepare(`
    SELECT
      COUNT(*)                                                                              AS total,
      SUM(CASE WHEN status = 'active' AND used_tokens < quota_tokens THEN 1 ELSE 0 END)     AS active,
      SUM(CASE WHEN status = 'exhausted' THEN 1 ELSE 0 END)                                 AS exhausted,
      SUM(CASE WHEN status = 'cooldown' OR status = 'disabled' THEN 1 ELSE 0 END)           AS paused,
      SUM(CASE WHEN status = 'disabled' THEN 1 ELSE 0 END)                                  AS disabled,
      SUM(used_tokens)                                                                      AS used_today,
      SUM(quota_tokens)                                                                     AS quota_total,
      SUM(CASE WHEN window_date = ? THEN quota_tokens - used_tokens ELSE 0 END)             AS remaining
    FROM keys
  `).get(t);
  const req = db.prepare("SELECT v FROM meta WHERE k = 'req_count'").get();
  return {
    today: t,
    keys: base || { total: 0, active: 0, exhausted: 0, paused: 0, disabled: 0, used_today: 0, quota_total: 0, remaining: 0 },
    requests_served: parseInt(req?.v || '0', 10),
  };
}

function bumpRequestCount() {
  db.prepare(`
    INSERT INTO meta (k, v) VALUES ('req_count', '1')
    ON CONFLICT(k) DO UPDATE SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT)
  `).run();
}

function countAll(filter = {}) {
  let sql = 'SELECT COUNT(*) c FROM keys WHERE 1=1';
  const args = [];
  if (filter.status) { sql += ' AND status = ?'; args.push(filter.status); }
  if (filter.upstreamId) { sql += ' AND upstream_id = ?'; args.push(parseInt(filter.upstreamId, 10)); }
  if (filter.q) { sql += ' AND (alias LIKE ? OR key LIKE ?)'; args.push(`%${filter.q}%`, `%${filter.q}%`); }
  return db.prepare(sql).get(...args).c;
}
function dbFile() { return db && db.name ? db.name : DB_PATH; }

// ── unified static token (single upstream key, NO rotation) ─────────
// When a static key is stored in meta, the proxy always sends that one
// token and never rotates the pool. It is only ever changed MANUALLY via
// the admin UI (or seeded once from STATIC_UPSTREAM_KEY on first run).
// Clearing it returns to rotating-pool mode. Stored AES-256-GCM-encrypted.
const STATIC_KEY_META = 'static_key';

/** Plaintext unified token, or null while static mode is off. */
function getStaticKey() {
  if (!db) return null;
  const row = db.prepare('SELECT v FROM meta WHERE k = ?').get(STATIC_KEY_META);
  if (row && row.v) {
    try { const p = kc.decrypt(row.v); if (p) return p; } catch { /* corrupt → fall through */ }
  }
  // first run: seed from env so the deploy works without manual setup
  const seed = String(process.env.STATIC_UPSTREAM_KEY || '').trim();
  if (seed) setStaticKey(seed);
  return seed || null;
}

/** Change the unified token manually. Empty clears → pool mode. */
function setStaticKey(plain) {
  const key = String(plain || '').trim();
  if (!key) return removeStaticKey();
  db.prepare(`
    INSERT INTO meta (k, v) VALUES (?, ?)
    ON CONFLICT(k) DO UPDATE SET v = excluded.v
  `).run(STATIC_KEY_META, kc.encrypt(key));
  return { enabled: true, masked: maskKey(key), mode: 'static', updated_at: new Date().toISOString() };
}

/** Remove the unified token → the proxy rotates the pool again. */
function removeStaticKey() {
  db.prepare('DELETE FROM meta WHERE k = ?').run(STATIC_KEY_META);
  return { enabled: false, masked: null, mode: 'pool' };
}

/** Status for the admin UI. */
function staticStatus() {
  if (!db) return { enabled: false, masked: null, mode: 'pool' };
  const plain = getStaticKey();
  if (!plain) return { enabled: false, masked: null, mode: 'pool' };
  return { enabled: true, masked: maskKey(plain), mode: 'static' };
}

module.exports = {
  init, addKey, addKeysBulk, pickKey, recordSuccess, recordFailure, recordCode, topUp,
  listKeys, listKeysRaw, getRow, toPublic, updateKey, deleteKey, resetUsage, stats,
  bumpRequestCount, countAll, maintenance, rawKey, maskKey, sha256, dbFile,
  getStaticKey, setStaticKey, removeStaticKey, staticStatus,
  listUpstreams, getUpstream, getUpstreamByName, addUpstream, updateUpstream,
  deleteUpstream, setUpstreamStaticKey,
  listModels, setModels, setModelEnabled, getUpstreamsForModel, listAllEnabledModels,
  config: { DEFAULT_QUOTA, FAIL_THRESHOLD, COOLDOWN_MS },
};
