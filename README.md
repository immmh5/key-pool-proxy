# Key Pool Proxy

A self-hosted API key load balancer / rotator / proxy pool for OpenAI-compatible providers (drop-in replacement for Cloudflare Workers).

- 🎯 Rotates keys on quota exhaustion / upstream errors
- 🛡️ Circuit breaker (temporary cooldown after repeated failures)
- 🔐 AES-256-GCM encryption of keys at rest
- 🔑 Single gateway endpoint, one persistent SQLite DB
- 🖥️ Web admin UI + REST admin API

## Quick start (local)

```bash
npm install
UPSTREAM_BASE_URL=https://api.example.com GATEWAY_TOKEN=g_123 ADMIN_TOKEN=a_456 \
KEY_ENC_SECRET=$(openssl rand -hex 32) node server.js
```

Then add your keys (via UI or curl):

```bash
curl -sS -H "x-admin-token: a_456" -X POST http://localhost:3000/admin/api/keys \
  -H 'Content-Type: text/plain' --data-binary @keys.txt
```

And call the gateway:

```bash
curl http://localhost:3000/v1/chat/completions \
  -H "Authorization: Bearer g_123" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

## Environment variables

| Var | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `UPSTREAM_BASE_URL` | — | **Required.** OpenAI-compatible base URL |
| `GATEWAY_TOKEN` | — | Token clients use to call `/v1/...` (if empty, gateway is open) |
| `ADMIN_TOKEN` | — | Token for `/admin` UI + API (if empty, admin is open) |
| `KEY_ENC_SECRET` | — | 32B hex random key; if empty, keys stored in plaintext |
| `DEFAULT_KEY_QUOTA` | `1000000` | Tokens per key per day |
| `FAIL_THRESHOLD` | `5` | Errors before circuit breaker trips |
| `COOLDOWN_MS` | `600000` | 10 min cooldown duration |

## Endpoints

**Gateway** (`GATEWAY_TOKEN`):
- `POST /v1/{...}` — any OpenAI-compatible path (proxy to upstream)

**Admin** (`ADMIN_TOKEN`):
- `GET  /admin/` — UI
- `GET  /admin/api/stats`
- `GET  /admin/api/keys?status=&q=&limit=&offset=`
- `POST /admin/api/keys` — JSON array / single key / plain text (one per line)
- `PATCH /admin/api/keys/:id` — `{alias,status,quota}`
- `DELETE /admin/api/keys/:id`
- `POST /admin/api/keys/:id/reset`
- `POST /admin/api/keys/:id/topup` — `{tokens}`
- `POST /admin/api/reset-all`
- `POST /admin/api/test` — `{id}` or `{key}` to validate against upstream

## Deploy on Render

Use the included `render.yaml` (Blueprint): it creates a web service with a 1 GB persistent disk at `/data` and injects the env vars above. Fill in the `generateValue` values after deploy, then add keys via the UI.

```bash
render blueprints validate --blueprintFile render.yaml   # optional, needs CLI/auth
```

See `render.yaml` for the full service definition.

## Notes

- Keys are stored **encrypted** only when `KEY_ENC_SECRET` is set. Without it, plaintext — don't run production without it.
- Quota resets automatically at midnight server time (`window_date`) — the Admin UI also has a manual "reset all".
- The proxy streams upstream responses and counts tokens with a simple local estimation (overhead ≈ model context length), serve streaming correctly.
