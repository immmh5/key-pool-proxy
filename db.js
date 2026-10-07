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

function nowMs() {
  return Date.now();
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
      created_at        TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_keys_sel ON keys(status, window_date, used_tokens);
    CREATE TABLE IF NOT EXISTS meta (
      k TEXT PRIMARY KEY,
      v TEXT
    );
  `);
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
function addKey({ key, alias = '', quota = DEFAULT_QUOTA }) {
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
             last_used_at = ?
       WHERE id = ?
    `).run(alias, alias, quota, today(), today(), now, existing.id);
    return db.prepare('SELECT * FROM keys WHERE id = ?').get(existing.id);
  }
  const info = db.prepare(`
    INSERT INTO keys (key, key_sha, alias, quota_tokens, window_date, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(stored, sha, alias, quota, today(), now);
  return db.prepare('SELECT * FROM keys WHERE id = ?').get(info.lastInsertRowid);
}

/** Bulk add — one transaction. Returns {added, updated}. */
function addKeysBulk(list, defaultQuota = DEFAULT_QUOTA) {
  const added = [], updated = [];
  const txn = db.transaction((rows) => {
    for (const r of rows) {
      const key = String(r.key || '').trim();
      if (!key) continue;
      const ex = db.prepare('SELECT id FROM keys WHERE key_sha = ?').get(sha256(key));
      const row = addKey({ key, alias: r.alias || '', quota: parseInt(r.quota, 10) || defaultQuota });
      if (!row) continue;
      (ex ? updated : added).push(row.id);
    }
  });
  txn(list);
  return { added, updated };
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
function pickKey() {
  const txn = db.transaction(() => {
    maintenance();
    const row = db.prepare(`
      SELECT * FROM keys
       WHERE status = 'active'
         AND used_tokens < quota_tokens
         AND cooldown_until <= ?
       ORDER BY used_tokens DESC, quota_tokens DESC, id ASC
       LIMIT 1
    `).get(nowMs());
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
function listKeys({ status, q, limit = 500, offset = 0 } = {}) {
  let sql = 'SELECT * FROM keys WHERE 1=1';
  const args = [];
  if (status) { sql += ' AND status = ?'; args.push(status); }
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
  const { status, alias, quota } = patch || {};
  db.prepare(`
    UPDATE keys SET
      status = COALESCE(?, status),
      alias = COALESCE(?, alias),
      quota_tokens = COALESCE(?, quota_tokens),
      cooldown_until = CASE WHEN ? = 'active' THEN 0 ELSE cooldown_until END,
      fail_count = CASE WHEN ? = 'active' THEN 0 ELSE fail_count END
     WHERE id = ?
  `).run(status ?? null, alias ?? null, quota ?? null, status ?? null, status ?? null, id);
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

function countAll() { return db.prepare('SELECT COUNT(*) c FROM keys').get().c; }
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
  listKeys, getRow, updateKey, deleteKey, resetUsage, stats,
  bumpRequestCount, countAll, maintenance, rawKey, maskKey, sha256, dbFile,
  getStaticKey, setStaticKey, removeStaticKey, staticStatus,
  config: { DEFAULT_QUOTA, FAIL_THRESHOLD, COOLDOWN_MS },
};
