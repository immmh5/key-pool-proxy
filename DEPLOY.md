# key-pool-proxy — Deployment

Live service on Render (Fleet Registry ACCT3).

| Field | Value |
|---|---|
| Service ID | `srv-db366som7kps73d60sb0` |
| URL | https://key-pool-proxy.onrender.com |
| Dashboard | https://dashboard.render.com/web/srv-db366som7kps73d60sb0 |
| Account | ACCT3 (`acct-c-3`, leader) |
| Plan | `free` (ephemeral filesystem) |
| Region | oregon |
| Runtime | node |
| Build | `npm ci` |
| Start | `node server.js` |
| Health check | `GET /health` |
| Auto-deploy | yes (on push to `main`) |

## Environment variables

Set on the service (values also in local gitignored `.env`):

- `PORT` = 3000
- `DB_PATH` = `./data/kpool.db`
- `UPSTREAM_BASE_URL` = `https://api.openai.com/v1`
- `GATEWAY_TOKEN`, `ADMIN_TOKEN`, `KEY_ENC_SECRET` — secrets (see `.env`)

## Notes

- **Free plan ⇒ ephemeral FS**: the SQLite DB at `DB_PATH` is wiped on every
  redeploy/suspend. Keys re-seed from code defaults on each boot.
- Manage via the Fleet Registry, not the Render dashboard directly:
  - Status: `GET https://render-fleet-registry.onrender.com/api/services/3`
  - Env vars: `GET|PUT .../api/services/3/srv-db366som7kps73d60sb0/envs`
  - Redeploy: `POST .../api/services/3/srv-db366som7kps73d60sb0/deploys`
