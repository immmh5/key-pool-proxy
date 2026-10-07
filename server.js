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
 *    UPSTREAM_BASE_URL   required — e.g. https://api.example.com/v1
 *    GATEWAY_TOKEN       optional auth token clients must send (Bearer)
 *    ADMIN_TOKEN         token guarding /admin/*
 *    PORT                default 13080
 *    DB_PATH             default ./data/key-pool.db
 *    DEFAULT_KEY_QUOTA   per-key tokens / 24h (default 1,000,000)
 *    UPSTREAM_TIMEOUT_MS default 120000
 *    KEY_ENC_SECRET      optional AES-256-GCM secret to encrypt keys at rest
 *    STATIC_UPSTREAM_KEY optional initial unified token (seeded once, manual changes only)
 */
const path = require('path');
const { Transform } = require('stream');
const express = require('express');
const cors = require('cors');
const db = require('./db');

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

// ── upstream secret resolution ── unified token or rotated pool ─────
// Static mode (a value in meta.static_key) always wins and never rotates;
// it is only changed manually via the admin UI. Otherwise fall back to the
// rotating pool as before.
function resolveUpstreamSecret() {
  const staticKey = db.getStaticKey();
  if (staticKey) return { mode: 'static', secret: staticKey, pick: null };
  const picked = db.pickKey();
  if (!picked) return null;
  return { mode: 'pool', secret: db.rawKey(picked), pick: picked };
}

// ── /health (for Render) ───────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true, keys: db.countAll(), mode: db.staticStatus().mode }));

app.get('/', (_req, res) => {
  const s = db.stats();
  res.json({ service: 'key-pool-proxy', upstream: UPSTREAM_BASE_URL || '(not set)', ...s });
});

// ── the OpenAI-compatible proxy ────────────────────────────────────
app.use('/v1', async (req, res) => {
  if (!gatewayOk(req)) {
    return res.status(401).json({ error: { message: 'Invalid gateway token', type: 'invalid_request_error' } });
  }
  if (!UPSTREAM_BASE_URL) {
    return res.status(500).json({ error: { message: 'UPSTREAM_BASE_URL is not configured', type: 'server_error' } });
  }

  // resolve upstream secret: unified static token (if set) else pool rotation
  const sel = resolveUpstreamSecret();
  if (!sel) {
    return res.status(429).json({
      error: {
        message: 'No upstream key available — set a static token or add pool keys. Try again later.',
        type: 'rate_limit_error',
        pool: db.stats().keys,
      },
    });
  }
  // static mode skips per-key accounting; pool mode records normally.
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

  const suffix = req.url === '/' ? '' : req.url;         // e.g. /chat/completions
  const target = UPSTREAM_BASE_URL + suffix;
  const countTokens = req.method === 'POST';

  let upstream;
  try {
    upstream = await fetch(target, {
      method: req.method,
      headers,
      body: (req.method === 'GET' || req.method === 'HEAD') ? undefined : bodyBuffer,
      redirect: 'follow',
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
  } catch (e) {
    const reason = e.name === 'TimeoutError' ? 'upstream timeout' : String(e.cause?.code || e.message).slice(0, 200);
    acc.fail(0, reason);
    return res.status(502).json({ error: { message: 'Upstream unreachable: ' + reason, type: 'upstream_error' } });
  }

  // classify upstream status
  const code = upstream.status;
  const keyFault = code === 401 || code === 403 || code === 429;

  // forward upstream headers
  const outHeaders = {};
  for (const [k, v] of upstream.headers) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    outHeaders[k] = v;
  }
  outHeaders['x-pool-key'] = isPool ? 'key-' + picked.id : 'static';
  res.status(code);

  const ctype = upstream.headers.get('content-type') || '';
  const isSSE = ctype.includes('text/event-stream');
  const ok = code >= 200 && code < 300;

  // apply forwarded headers (includes x-pool-key) on both paths
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

    upstream.body.pipe(tracker).pipe(res);

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
    upstream.body.on('end', done);
    upstream.body.on('error', () => {
      if (ok) acc.fail(0, 'stream aborted mid-response');
      else if (keyFault) acc.fail(code, 'upstream ' + code);
      else acc.code(code, 'stream aborted');
    });
    return;
  }

  // ── non-stream: buffer, parse usage from JSON body ──
  let text;
  try { text = await upstream.text(); } catch (e) {
    acc.fail(0, 'failed reading upstream body');
    return res.json({ error: { message: 'upstream read failure', type: 'upstream_error' } });
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
});

// ── admin panel (static) ───────────────────────────────────────────
app.get('/admin/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ── admin API ──────────────────────────────────────────────────────
const admin = express.Router();
admin.use((req, res, next) => (adminOk(req) ? next() : res.status(401).json({ error: 'ADMIN_TOKEN required' })));

admin.get('/stats', (_req, res) => res.json(db.stats()));

admin.get('/keys', (req, res) => {
  const { status, q } = req.query;
  const limit = Math.min(parseInt(req.query.limit, 10) || 500, 2000);
  const offset = parseInt(req.query.offset, 10) || 0;
  res.json({ keys: db.listKeys({ status, q, limit, offset }), total: db.countAll() });
});

admin.post('/keys', async (req, res) => {
  // accepts: {keys:[...]} | {key,alias?,quota?} | raw text (one key per line)
  let items = [];
  if (Array.isArray(req.body?.keys)) items = req.body.keys;
  else if (typeof req.body?.key === 'string') items = [{ key: req.body.key, alias: req.body.alias, quota: req.body.quota }];
  else if (typeof req.body === 'string' || (req.is('text/*'))) {
    items = String(req.body).split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((key) => ({ key }));
  }
  if (!items.length) return res.status(400).json({ error: 'Provide keys: JSON array, single key, or plain text (one per line)' });
  const { added, updated } = db.addKeysBulk(items.map((i) => ({
    key: i.key, alias: i.alias || '', quota: parseInt(i.quota, 10) || undefined,
  })));
  res.json({ added, updated, invalid: items.length - added.length - updated.length });
});

admin.patch('/keys/:id', (req, res) => {
  const row = db.updateKey(parseInt(req.params.id, 10), req.body);
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

// validate a key against the upstream (GET /models) without touching the pool
admin.post('/test', async (req, res) => {
  const id = parseInt(req.body?.id, 10);
  const key = (req.body?.key || '').trim();
  if (!id && !key) return res.status(400).json({ error: 'provide {id} or {key}' });
  const secret = id ? db.rawKey(db.getRow(id)) : key;
  try {
    const r = await fetch(UPSTREAM_BASE_URL + '/models', {
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

// ── boot ───────────────────────────────────────────────────────────
db.init();
app.listen(PORT, () => {
  console.log(`[key-pool-proxy] listening on :${PORT}`);
  console.log(`[key-pool-proxy] upstream      : ${UPSTREAM_BASE_URL || 'NOT SET — set UPSTREAM_BASE_URL'}`);
  console.log(`[key-pool-proxy] gateway auth  : ${GATEWAY_TOKEN ? 'enabled' : 'DISABLED (open — set GATEWAY_TOKEN)'}`);
  console.log(`[key-pool-proxy] admin auth    : ${ADMIN_TOKEN ? 'enabled' : 'DISABLED (open — set ADMIN_TOKEN)'}`);
  console.log(`[key-pool-proxy] keys in pool  : ${db.countAll()}`);
  console.log(`[key-pool-proxy] encryption    : ${require('./crypto').enabled() ? 'AES-256-GCM' : 'plaintext (set KEY_ENC_SECRET)'}`);
  const sts = db.staticStatus();
  console.log(`[key-pool-proxy] upstream mode : ${sts.enabled ? 'STATIC — single unified token (manual only, no rotation)' : 'pool rotation'}`);
});
