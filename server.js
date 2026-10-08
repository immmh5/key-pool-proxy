'use strict';
/**
 * key-pool-proxy — self-hosted API Key Load Balancer / Rotator.
 *
 *  Exposes an OpenAI-compatible `/v1/*` surface to your apps and
 *  (a) forwards a single UNIFIED static token when one is set via the admin
 *      UI — changed only MANUALLY, never auto-rotated — or (b) rotates
 *  through a pool of upstream keys stored in SQLite otherwise. Tracks per-key
 *  token usage from the upstream `usage` object (JSON and SSE), rotates on
 *  quota exhaustion, and applies a circuit breaker on failing keys.
 *
 *  Env:
 *    UPSTREAMS          optional — JSON array of upstream definitions, e.g.
 *                       [{"name":"deepseek","baseUrl":"https://api.deepseek.com/v1",
 *                         "priority":1,"staticKey":"sk-...","models":["deepseek-chat"]},
 *                        {"name":"openai","baseUrl":"https://api.openai.com/v1","priority":2}]
 *                       Also accepts base_url/static_key/models/api_key spellings.
 *    UPSTREAM_BASE_URL  optional legacy fallback — seeds a single "default" upstream
 *    STATIC_UPSTREAM_KEY optional initial static token for that default upstream
 *    GATEWAY_TOKEN      optional auth token clients must send (Bearer)
 *    ADMIN_TOKEN        token guarding /admin/*
 *    PORT               default 13080
 *    DB_PATH            default ./data/key-pool.db
 *    DEFAULT_KEY_QUOTA  per-key tokens / 24h (default 1,000,000)
 *    UPSTREAM_TIMEOUT_MS default 120000
 *    KEY_ENC_SECRET     optional AES-256-GCM secret to encrypt keys at rest
 */
const path = require('path');
const { Transform } = require('stream');
const express = require('express');
const cors = require('cors');
const db = require('./db');
const kc = require('./crypto');

// ── config ─────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '13080', 10);
const UPSTREAM_BASE_URL = (process.env.UPSTREAM_BASE_URL || '').replace(/\/+$/, '');
const GATEWAY_TOKEN = process.env.GATEWAY_TOKEN || '';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const UPSTREAM_TIMEOUT_MS = parseInt(process.env.UPSTREAM_TIMEOUT_MS || '120000', 10);
const MAX_BODY = (parseInt(process.env.MAX_BODY_MB || '25', 10)) * 1024 * 1024;

const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'content-encoding', 'content-length',
]);

const app = express();
app.use(cors());
// /v1 MUST be handled before any body parser: the proxy route consumes the raw
// stream itself (readBody is not used — req.body is a Buffer here).
app.use('/v1', (req, res, next) => {
  express.raw({ type: () => true, limit: MAX_BODY })(req, res, (err) => {
    if (err) return res.status(413).json({ error: { message: 'Request body too large', type: 'invalid_request_error' } });
    next();
  });
});
app.use(express.json({ limit: '1mb' }));
app.use(express.text({ type: 'text/plain', limit: '1mb' }));

// ── helpers ────────────────────────────────────────────────────────
function publicRow(r) {
  if (!r) return null;
  return {
    id: r.id, alias: r.alias, quota: r.quota_tokens, used_tokens: r.used_tokens,
    remaining: Math.max(0, (r.quota_tokens || 0) - r.used_tokens),
    percent: r.quota_tokens > 0 ? Math.round((r.used_tokens / r.quota_tokens) * 10000) / 100 : 0,
    status: r.status, fail_count: r.fail_count, cooldown_until: r.cooldown_until,
    last_used_at: r.last_used_at, last_code: r.last_code, last_error: r.last_error,
  };
}

function extractModels(body) {
  try {
    const j = JSON.parse(body);
    return Array.isArray(j?.data)
      ? j.data.map((m) => m.id).join(', ')
      : 'no models array in response';
  } catch { return 'non-JSON response'; }
}

function estimateTokens(str) {
  const s = String(str || '');
  return Math.max(1, Math.ceil(s.length / 4)); // ~4 chars/token heuristic
}

function tokensFromUsage(u) {
  if (!u) return null;
  const t = u.total_tokens ?? ((u.prompt_tokens || 0) + (u.completion_tokens || 0));
  return Number.isFinite(t) && t > 0 ? Math.round(t) : null;
}

function readBody(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', (c) => {
      total += c.length;
      if (total > cap) { const e = new Error('body too large'); e.status = 413; reject(e); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function gatewayOk(req) {
  if (!GATEWAY_TOKEN) return true;
  const auth = req.headers.authorization || '';
  const qk = typeof req.query.api_key === 'string' ? req.query.api_key : '';
  const bearer = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
  return bearer === GATEWAY_TOKEN || qk === GATEWAY_TOKEN;
}

function adminOk(req) {
  if (!ADMIN_TOKEN) return true; // open admin — discouraged
  const auth = req.headers.authorization || '';
  const xt = req.headers['x-admin-token'];
  return auth === `Bearer ${ADMIN_TOKEN}` || xt === ADMIN_TOKEN;
}

// ── upstream secret resolution ──────────────────────────────────────
// Per upstream: a configured static token (never rotated, manual-only) wins;
// otherwise we draw from that upstream's key pool. Returns null when this
// upstream has nothing to offer right now — the router then fails over to the
// next candidate upstream in priority order.
function resolveUpstreamSecret(upstream) {
  if (upstream.static_key) {
    const plain = kc.decrypt(upstream.static_key);
    if (plain) return { mode: 'static', secret: plain, pick: null, upstream };
  }
  const picked = db.pickKey(upstream.id);
  if (!picked) return null;
  return { mode: 'pool', secret: db.rawKey(picked), pick: picked, upstream };
}

// ── /health (for Render) ───────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true, keys: db.countAll(), mode: db.staticStatus().mode }));

app.get('/', (_req, res) => {
  const s = db.stats();
  res.json({ service: 'key-pool-proxy', version: require('./package.json').version,
             gatewayAuth: Boolean(GATEWAY_TOKEN), upstreams: db.listUpstreams().length, ...s });
});

// ── the OpenAI-compatible proxy ────────────────────────────────────
// Routing:
//   1. GET /v1/models → union of every upstream's enabled models (intercepted).
//   2. Explicit path:  /v1/<upstream-name>/<...> → that upstream only.
//   3. Model-based:    the `model` field of the request body → the upstreams
//                      that whitelist that model, ordered by priority.
//   4. Fallback:       all enabled upstreams in priority order.
// Once a candidate upstream is chosen we resolve its secret; if it has none
// (no static token and its pool is drained) we fail over to the next candidate.
function readModelFromBody(body) {
  if (!Buffer.isBuffer(body) || !body.length) return null;
  try {
    const j = JSON.parse(body.toString('utf8'));
    if (j && typeof j.model === 'string') return j.model;
  } catch { /* non-JSON body — nothing to route on */ }
  return null;
}

function resolveCandidates(req) {
  const url = req.url; // e.g. /chat/completions or /deepseek/chat/completions

  // (2) explicit upstream name in the path
  const seg = url.startsWith('/') ? url.slice(1).split('/')[0] : '';
  const named = seg ? db.getUpstreamByName(seg) : null;
  if (named) {
    if (!named.enabled) return [];
    const suffix = url.slice(1 + seg.length);
    return [{ upstream: named, suffix }];
  }

  // (3) model whitelist
  const model = readModelFromBody(req.body);
  if (model) {
    const ups = db.getUpstreamsForModel(model);
    if (ups.length) return ups.map((u) => ({ upstream: u, suffix: url }));
    // No whitelist configured anywhere yet → behave as a plain priority router
    // (this keeps a freshly seeded single upstream working out of the box).
    if (!db.listAllEnabledModels().length) {
      return db.listUpstreams().filter((u) => u.enabled).map((u) => ({ upstream: u, suffix: url }));
    }
    return []; // model is whitelisted-out / unknown → 404 below
  }

  // (4) no model hint → try every enabled upstream in priority order
  return db.listUpstreams().filter((u) => u.enabled).map((u) => ({ upstream: u, suffix: url }));
}

// The actual upstream call for one candidate. Sends the response itself and
// returns { handled: true }. Returns { handled: false } only when the fetch
// failed at the network level (no response was produced) — in that case the
// caller may try the next candidate.
async function forwardTo(req, res, upstream, suffix, sel) {
  const isPool = sel.mode === 'pool';
  const picked = isPool ? sel.pick : null;
  const acc = isPool
    ? {
        ok: (t) => db.recordSuccess(picked.id, t),
        fail: (c, m) => db.recordFailure(picked.id, c, m),
        code: (c, m) => db.recordCode(picked.id, c, m),
      }
    : { ok: () => {}, fail: () => {}, code: () => {} };

  // forward headers minus hop-by-hop / host / auth
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk) || lk === 'host' || lk === 'authorization' || lk === 'accept-encoding') continue;
    headers[lk] = v;
  }
  headers.authorization = `Bearer ${sel.secret}`;

  // body is a Buffer captured by the scoped express.raw() parser (handles limit 413)
  let bodyBuffer = req.body instanceof Buffer ? req.body : Buffer.alloc(0);
  if (bodyBuffer.length) headers['content-length'] = String(bodyBuffer.length);

  const target = upstream.base_url + (suffix.startsWith('/') ? suffix : '/' + suffix);
  const countTokens = req.method === 'POST';

  let resp;
  try {
    resp = await fetch(target, {
      method: req.method,
      headers,
      body: (req.method === 'GET' || req.method === 'HEAD') ? undefined : bodyBuffer,
      redirect: 'follow',
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
  } catch (e) {
    const reason = e.name === 'TimeoutError' ? 'upstream timeout' : String(e.cause?.code || e.message).slice(0, 200);
    acc.fail(0, reason);
    return { handled: false, networkError: reason };
  }

  // classify upstream status
  const code = resp.status;
  const keyFault = code === 401 || code === 403 || code === 429;

  // forward upstream headers
  const outHeaders = {};
  for (const [k, v] of resp.headers) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    outHeaders[k] = v;
  }
  outHeaders['x-pool-key'] = isPool ? 'key-' + picked.id : 'static';
  outHeaders['x-pool-upstream'] = upstream.name;
  res.status(code);

  const ctype = resp.headers.get('content-type') || '';
  const isSSE = ctype.includes('text/event-stream');
  const ok = code >= 200 && code < 300;

  // apply forwarded headers (includes x-pool-key / x-pool-upstream) on both paths
  for (const [k, v] of Object.entries(outHeaders)) res.setHeader(k, v);

  // ── SSE: stream through, capture trailing usage chunk ──
  if (isSSE) {
    res.flushHeaders?.();
    let usage = null;
    let bytes = 0;
    const tracker = new Transform({
      transform(chunk, _enc, cb) {
        bytes += chunk.length;
        const text = chunk.toString('utf8');
        const lines = text.match(/data:\s*[^\n\r]+/g) || [];
        for (const d of lines) {
          const json = d.replace(/^data:\s*/, '');
          if (json === '[DONE]') continue;
          try {
            const obj = JSON.parse(json);
            if (obj && obj.usage) usage = obj.usage;
          } catch { /* partial line — ignore */ }
        }
        cb(null, chunk);
      },
    });

    resp.body.pipe(tracker).pipe(res);

    const done = () => {
      if (ok) {
        const tokens = tokensFromUsage(usage) ?? (countTokens ? estimateTokens(bodyBuffer.toString('utf8')) + Math.ceil(bytes / 4) : 0);
        acc.ok(tokens);
        db.bumpRequestCount();
      } else if (keyFault) {
        acc.fail(code, 'upstream ' + code);
      } else {
        acc.code(code, 'upstream ' + code);
      }
    };
    resp.body.on('end', done);
    resp.body.on('error', () => {
      if (ok) acc.fail(0, 'stream aborted mid-response');
      else if (keyFault) acc.fail(code, 'upstream ' + code);
      else acc.code(code, 'stream aborted');
    });
    return { handled: true };
  }

  // ── non-stream: buffer, parse usage from JSON body ──
  let text;
  try { text = await resp.text(); } catch (e) {
    acc.fail(0, 'failed reading upstream body');
    res.json({ error: { message: 'upstream read failure', type: 'upstream_error' } });
    return { handled: true };
  }
  res.setHeader('content-length', Buffer.byteLength(text));
  res.send(text);

  if (ok) {
    let usage = null;
    try {
      const parsed = JSON.parse(text);
      if (parsed && parsed.usage) usage = parsed.usage;
    } catch { /* not JSON */ }
    const tokens = tokensFromUsage(usage) ?? (countTokens ? estimateTokens(bodyBuffer.toString('utf8')) + estimateTokens(text) : 0);
    acc.ok(tokens);
    db.bumpRequestCount();
  } else if (keyFault) {
    acc.fail(code, 'upstream ' + code);
  } else {
    acc.code(code, 'upstream ' + code);
  }
  return { handled: true };
}

app.use('/v1', async (req, res) => {
  if (!gatewayOk(req)) {
    return res.status(401).json({ error: { message: 'Invalid gateway token', type: 'invalid_request_error' } });
  }

  // GET /v1/models → the union of every enabled upstream's whitelisted models.
  if (req.method === 'GET' && /^\/models\/?$/.test(req.url)) {
    const rows = db.listAllEnabledModels();
    return res.json({
      object: 'list',
      data: rows.map((m) => ({
        id: m.id,
        object: 'model',
        created: 0,
        owned_by: 'key-pool-proxy',
        upstreams: String(m.owners || '').split(',').filter(Boolean),
      })),
    });
  }

  const candidates = resolveCandidates(req);
  if (!candidates.length) {
    return res.status(404).json({
      error: {
        message: 'No enabled upstream serves this model/path. Configure upstreams and their model whitelist in the admin panel.',
        type: 'invalid_request_error',
      },
    });
  }

  // Try each candidate in failover order; skip upstreams that have no key right now.
  let lastNetError = null;
  for (let i = 0; i < candidates.length; i++) {
    const { upstream, suffix } = candidates[i];
    const sel = resolveUpstreamSecret(upstream);
    if (!sel) continue;               // drained → next upstream
    const r = await forwardTo(req, res, upstream, suffix, sel);
    if (r.handled) return;            // response is out the door
    lastNetError = r.networkError;    // upstream was unreachable → try next
  }

  if (lastNetError) {
    return res.status(502).json({ error: { message: 'Upstream unreachable: ' + lastNetError, type: 'upstream_error' } });
  }
  return res.status(429).json({
    error: {
      message: `No upstream key available for: ${candidates.map((c) => c.upstream.name).join(', ')}. All pools are drained/cooling down — try again later.`,
      type: 'rate_limit_error',
      pool: db.stats().keys,
    },
  });
});

// ── admin panel (static) ───────────────────────────────────────────
app.get('/admin/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ── admin API ──────────────────────────────────────────────────────
const admin = express.Router();
admin.use((req, res, next) => (adminOk(req) ? next() : res.status(401).json({ error: 'ADMIN_TOKEN required' })));

admin.get('/stats', (_req, res) => res.json(db.stats()));

// ── upstream registry ───────────────────────────────────────────────
// GET    /upstreams          → list all with key/model counts
// POST   /upstreams          → create {name, baseUrl, priority?, enabled?, staticKey?, models?}
// GET    /upstreams/:id      → one upstream + its model whitelist
// PATCH  /upstreams/:id      → update fields (staticKey '' clears it)
// DELETE /upstreams/:id      → remove it, its whitelist and its keys
// PUT    /upstreams/:id/models           → replace the whitelist {models:[...]}
// POST   /upstreams/:id/models/:m/toggle → {enabled:bool}
// POST   /upstreams/:id/fetch-models     → probe the upstream GET /models and import the ids
admin.get('/upstreams', (_req, res) => {
  res.json(db.listUpstreams().map((u) => ({
    id: u.id, name: u.name, base_url: u.base_url, enabled: !!u.enabled, priority: u.priority,
    static_key: u.static_key ? '[static token set]' : '',
    key_count: u.key_count, model_count: u.model_count, created_at: u.created_at,
  })));
});

admin.post('/upstreams', (req, res) => {
  const { name, baseUrl, priority, enabled, staticKey, models } = req.body || {};
  if (!name || !baseUrl) return res.status(400).json({ error: 'name and baseUrl are required' });
  const u = db.addUpstream({ name, baseUrl, priority, enabled: enabled === false ? 0 : 1, staticKey: staticKey || '' });
  if (!u) return res.status(400).json({ error: 'invalid upstream (check name/baseUrl)' });
  if (Array.isArray(models) && models.length) db.setModels(u.id, models);
  res.json({ ...u, static_key: u.static_key ? '[static token set]' : '' });
});

admin.get('/upstreams/:id', (req, res) => {
  const u = db.getUpstream(parseInt(req.params.id, 10));
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json({
    id: u.id, name: u.name, base_url: u.base_url, enabled: !!u.enabled, priority: u.priority,
    static_key: u.static_key ? '[static token set]' : '',
    models: db.listModels(u.id),
    keys: db.listKeys({ limit: 2000, offset: 0 }).filter((k) => k.upstream_id === u.id),
  });
});

admin.patch('/upstreams/:id', (req, res) => {
  const b = req.body || {};
  const { name, priority, enabled } = b;
  const baseUrl = b.baseUrl ?? b.base_url;
  const staticKey = b.staticKey ?? b.static_key;
  const u = db.updateUpstream(parseInt(req.params.id, 10), { name, baseUrl, priority, enabled, staticKey });
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json({ ...u, static_key: u.static_key ? '[static token set]' : '' });
});

admin.delete('/upstreams/:id', (req, res) => {
  res.json({ deleted: db.deleteUpstream(parseInt(req.params.id, 10)) });
});

admin.put('/upstreams/:id/models', (req, res) => {
  const { models } = req.body || {};
  if (!Array.isArray(models) && typeof models !== 'string') return res.status(400).json({ error: 'models array (or comma string) required' });
  res.json(db.setModels(parseInt(req.params.id, 10), models));
});

admin.post('/upstreams/:id/models/:model/toggle', (req, res) => {
  const enabled = req.body?.enabled === false ? 0 : 1;
  res.json(db.setModelEnabled(parseInt(req.params.id, 10), decodeURIComponent(req.params.model), enabled));
});

// Probe an upstream's GET /v1/models and return its model ids (read-only).
// Uses the upstream's static key if set, otherwise its least-used pool key.
async function probeUpstreamModels(u) {
  if (!u) throw Object.assign(new Error('not found'), { code: 'not_found' });
  let secret = null;
  if (u.static_key) {
    const plain = kc.decrypt(u.static_key);
    if (plain) secret = plain;
  }
  if (!secret) {
    const picked = db.pickKey(u.id);
    if (picked) secret = db.rawKey(picked);
  }
  if (!secret) throw Object.assign(new Error('no key available for this upstream to probe with'), { code: 'no_key' });
  const base = u.base_url.replace(/\/+$/, '');
  const r = await fetch(base + '/models', {
    headers: { authorization: `Bearer ${secret}` },
    signal: AbortSignal.timeout(20000),
  });
  const body = await r.text();
  if (!r.ok) {
    const err = new Error('upstream responded ' + r.status);
    err.code = 'upstream_' + r.status;
    err.raw = body.slice(0, 300);
    throw err;
  }
  const data = JSON.parse(body).data || [];
  return data.map((m) => m.id).filter(Boolean).sort((a, b) => a.localeCompare(b));
}

// read-only discovery: list what the upstream offers vs. what's whitelisted
admin.get('/upstreams/:id/models/available', async (req, res) => {
  const u = db.getUpstream(parseInt(req.params.id, 10));
  if (!u) return res.status(404).json({ error: 'not found' });
  try {
    const ids = await probeUpstreamModels(u);
    const enabled = new Set(db.listModels(u.id, true).map((m) => m.model));
    const known = new Set(db.listModels(u.id).map((m) => m.model));
    res.json({
      base_url: u.base_url,
      fetched: ids.length,
      models: ids.map((id) => ({ id, whitelisted: known.has(id), enabled: enabled.has(id) })),
    });
  } catch (e) {
    const status = String(e.code || '').startsWith('upstream_') ? Number(String(e.code).slice(9)) || 502 : 502;
    res.status(e.code === 'not_found' ? 404 : e.code === 'no_key' ? 400 : status)
       .json({ error: 'fetch failed: ' + (e.cause?.code || e.message), raw: e.raw || undefined });
  }
});

// legacy: probe + import everything (replaces the whitelist)
admin.post('/upstreams/:id/fetch-models', async (req, res) => {
  const u = db.getUpstream(parseInt(req.params.id, 10));
  if (!u) return res.status(404).json({ error: 'not found' });
  try {
    const ids = await probeUpstreamModels(u);
    const kept = db.setModels(u.id, ids);
    res.json({ fetched: ids.length, models: kept });
  } catch (e) {
    res.status(502).json({ error: 'fetch failed: ' + (e.cause?.code || e.message), raw: e.raw || undefined });
  }
});

admin.get('/keys', (req, res) => {
  const { status, q, upstream_id } = req.query;
  const limit = Math.min(parseInt(req.query.limit, 10) || 500, 2000);
  const offset = parseInt(req.query.offset, 10) || 0;
  const filter = { status, q, upstreamId: upstream_id };
  res.json({ keys: db.listKeys({ ...filter, limit, offset }), total: db.countAll(filter) });
});

admin.post('/keys', async (req, res) => {
  // accepts: {keys:[...]} | {key,alias?,quota?} | raw text (one key per line)
  // optional {upstream_id} binds the batch to one upstream
  let items = [];
  if (Array.isArray(req.body?.keys)) items = req.body.keys;
  else if (typeof req.body?.key === 'string') items = [{ key: req.body.key, alias: req.body.alias, quota: req.body.quota }];
  else if (typeof req.body === 'string' || (req.is('text/*'))) {
    items = String(req.body).split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((key) => ({ key }));
  }
  if (!items.length) return res.status(400).json({ error: 'Provide keys: JSON array, single key, or plain text (one per line)' });
  const upstreamId = parseInt(req.body?.upstream_id, 10) || null;
  const { added, updated } = db.addKeysBulk(items.map((i) => ({
    key: i.key, alias: i.alias || '', quota: parseInt(i.quota, 10) || undefined,
  })), undefined, upstreamId);
  res.json({ added, updated, invalid: items.length - added.length - updated.length });
});

admin.get('/keys/:id', (req, res) => {
  const row = db.getRow(parseInt(req.params.id, 10));
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(db.toPublic(row));
});

admin.patch('/keys/:id', (req, res) => {  const row = db.updateKey(parseInt(req.params.id, 10), req.body);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(publicRow(row));
});

admin.delete('/keys/:id', (req, res) => {
  res.json({ deleted: db.deleteKey(parseInt(req.params.id, 10)) });
});

admin.post('/keys/:id/reset', (req, res) => {
  res.json({ reset: db.resetUsage(parseInt(req.params.id, 10)) });
});

admin.post('/keys/:id/topup', (req, res) => {
  const tokens = parseInt(req.body?.tokens, 10);
  if (!tokens || tokens <= 0) return res.status(400).json({ error: 'tokens required (>0)' });
  const row = db.topUp(parseInt(req.params.id, 10), tokens);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(publicRow(row));
});

admin.post('/reset-all', (_req, res) => res.json({ reset: db.resetUsage(null) }));

// validate a key against a specific upstream (GET /models) without touching the pool
admin.post('/test', async (req, res) => {
  const id = parseInt(req.body?.id, 10);
  const upstreamId = parseInt(req.body?.upstream_id, 10);
  const key = (req.body?.key || '').trim();
  if (!id && !key) return res.status(400).json({ error: 'provide {id} or {key}' });
  let target = null;
  if (upstreamId) {
    const u = db.getUpstream(upstreamId);
    if (u) target = u.base_url;
  }
  if (!target) target = (db.listUpstreams().find((u) => u.enabled) || {}).base_url;
  if (!target) return res.status(400).json({ error: 'no upstream configured to test against' });
  const secret = id ? db.rawKey(db.getRow(id)) : key;
  try {
    const r = await fetch(target.replace(/\/+$/, '') + '/models', {
      headers: { authorization: `Bearer ${secret}` },
      signal: AbortSignal.timeout(20000),
    });
    const body = await r.text();
    res.json({ ok: r.ok, status: r.status, models: extractModels(body), raw: body.slice(0, 300) });
  } catch (e) {
    res.status(502).json({ error: 'test failed: ' + (e.cause?.code || e.message) });
  }
});

app.use('/admin/api', admin);

// ── unified static token admin endpoints ───────────────────────────
// GET    → status {enabled, masked, mode}
// POST   → set (manual change; body {key})
// DELETE → clear → pools rotate again
app.get('/admin/api/static', (_req, res) => {
  if (!adminOk(_req)) return res.status(401).json({ error: 'ADMIN_TOKEN required' });
  res.json(db.staticStatus());
});
app.post('/admin/api/static', express.json(), (req, res) => {
  if (!adminOk(req)) return res.status(401).json({ error: 'ADMIN_TOKEN required' });
  const key = String(req.body?.key || '').trim();
  if (!key) return res.status(400).json({ error: 'Provide {key}' });
  res.json(db.setStaticKey(key));
});
app.delete('/admin/api/static', (_req, res) => {
  if (!adminOk(_req)) return res.status(401).json({ error: 'ADMIN_TOKEN required' });
  res.json(db.removeStaticKey());
});

// ── 404 ────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: { message: 'Not found', type: 'not_found' } }));

// ── last-resort error handler: never let one bad request kill the proxy ─
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[key-pool-proxy] request error:', err && err.message ? err.message : err);
  res.status(500).json({ error: { message: 'Internal error', type: 'server_error' } });
});
process.on('uncaughtException', (e) => console.error('[key-pool-proxy] uncaughtException (surviving):', e && e.stack ? e.stack : e));
process.on('unhandledRejection', (e) => console.error('[key-pool-proxy] unhandledRejection (surviving):', e && e.stack ? e.stack : e));

// ── boot ───────────────────────────────────────────────────────────
db.init();
app.listen(PORT, () => {
  console.log(`[key-pool-proxy] listening on :${PORT}`);
  const ups = db.listUpstreams();
  console.log(`[key-pool-proxy] upstreams     : ${ups.length ? ups.map((u) => u.name + '(' + u.key_count + 'k,' + u.model_count + 'm)').join(' ') : 'NONE — set UPSTREAMS or UPSTREAM_BASE_URL'}`);
  console.log(`[key-pool-proxy] gateway auth  : ${GATEWAY_TOKEN ? 'enabled' : 'DISABLED (open — set GATEWAY_TOKEN)'}`);
  console.log(`[key-pool-proxy] admin auth    : ${ADMIN_TOKEN ? 'enabled' : 'DISABLED (open — set ADMIN_TOKEN)'}`);
  console.log(`[key-pool-proxy] keys in pool  : ${db.countAll()}`);
  console.log(`[key-pool-proxy] encryption    : ${require('./crypto').enabled() ? 'AES-256-GCM' : 'plaintext (set KEY_ENC_SECRET)'}`);
  const sts = db.staticStatus();
  console.log(`[key-pool-proxy] upstream mode : ${sts.enabled ? 'STATIC — single unified token (manual only, no rotation)' : 'pool rotation'}`);
});
