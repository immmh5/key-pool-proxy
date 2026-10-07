#!/usr/bin/env bash
# End-to-end local test: mock upstream + key pool proxy + import 400 keys + rotation.
set -eu
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PORT_UP=4010
PORT_PX=4300
DB=/tmp/kpool-test.db
rm -f "$DB" "$DB-wal" "$DB-shm"

cleanup() { kill ${UP_PID:-} ${PX_PID:-} 2>/dev/null || true; }
trap cleanup EXIT

echo "== starting mock upstream on :$PORT_UP =="
node test/mock-upstream.js >/tmp/mock-up.log 2>&1 &
UP_PID=$!

echo "== starting key pool proxy on :$PORT_PX =="
PORT="$PORT_PX" \
DB_PATH="$DB" \
UPSTREAM_BASE_URL="http://127.0.0.1:$PORT_UP/v1" \
GATEWAY_TOKEN=g_tok ADMIN_TOKEN=a_tok \
KEY_ENC_SECRET="$(openssl rand -hex 32)" \
DEFAULT_KEY_QUOTA=1000 FAIL_THRESHOLD=3 COOLDOWN_MS=2000 \
node server.js >/tmp/kpool.log 2>&1 &
PX_PID=$!

echo "== waiting for ports =="
for i in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PORT_UP/v1/models" >/dev/null 2>&1 && break
  sleep 0.2
done
for i in $(seq 1 50); do
  curl -fsS -H "x-admin-token: a_tok" "http://127.0.0.1:$PORT_PX/admin/api/stats" >/dev/null 2>&1 && break
  sleep 0.2
done

# 1) import 400 keys (plain text, one per line) via the raw-text path
echo "== importing 400 keys (text/plain) =="
seq 1 400 | sed 's/^/sk-mock-key-/' > /tmp/kpool-keys.txt
curl -fsS -H "x-admin-token: a_tok" -H 'Content-Type: text/plain' \
  --data-binary @/tmp/kpool-keys.txt "http://127.0.0.1:$PORT_PX/admin/api/keys"
echo

STATS=$(curl -fsS -H "x-admin-token: a_tok" "http://127.0.0.1:$PORT_PX/admin/api/stats")
echo "stats: $STATS"
echo "$STATS" | grep -q '"total":400' && echo "PASS: 400 keys imported" || { echo "FAIL: import count"; exit 1; }

# also test JSON-array import
echo "== importing via JSON array =="
curl -fsS -H "x-admin-token: a_tok" -H 'Content-Type: application/json' \
  -d '{"keys":[{"key":"sk-json-1","alias":"json1"},{"key":"sk-json-2","alias":"json2"}]}' \
  "http://127.0.0.1:$PORT_PX/admin/api/keys"
echo

# 2) rotation: quota=1000, each request charges 600 -> 2 requests exhaust key A, 3rd goes to key B
echo "== rotation test (quota 1000, charge 600/req) =="
K1=$(curl -fsS -H "Authorization: Bearer g_tok" -H 'X-Tokens: 600' \
     -d '{"model":"mock-model","messages":[{"role":"user","content":"hi"}]}' \
     -H 'Content-Type: application/json' "http://127.0.0.1:$PORT_PX/v1/chat/completions" -o /dev/null -D - \
     | grep -i '^x-pool-key:' | tr -d '\r')
echo "req1 -> $K1"
K2=$(curl -fsS -H "Authorization: Bearer g_tok" -H 'X-Tokens: 600' \
     -d '{"model":"mock-model","messages":[{"role":"user","content":"hi"}]}' \
     -H 'Content-Type: application/json' "http://127.0.0.1:$PORT_PX/v1/chat/completions" -o /dev/null -D - \
     | grep -i '^x-pool-key:' | tr -d '\r')
echo "req2 -> $K2"
K3=$(curl -fsS -H "Authorization: Bearer g_tok" -H 'X-Tokens: 600' \
     -d '{"model":"mock-model","messages":[{"role":"user","content":"hi"}]}' \
     -H 'Content-Type: application/json' "http://127.0.0.1:$PORT_PX/v1/chat/completions" -o /dev/null -D - \
     | grep -i '^x-pool-key:' | tr -d '\r')
echo "req3 -> $K3"
echo "req1=$K1 req2=$K2 req3=$K3"
[ "$K1" = "$K2" ] && [ "$K2" != "$K3" ] && echo "PASS: rotation after exhaustion" || { echo "FAIL: expected K1==K2 != K3"; exit 1; }

# key A should now be exhausted in the DB
curl -fsS -H "x-admin-token: a_tok" "http://127.0.0.1:$PORT_PX/admin/api/keys?status=exhausted&limit=5" | grep -o '"alias":"[^"]*"' | head -1
echo "== done =="
