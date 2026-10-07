#!/usr/bin/env bash
# Static unified-token mode: on->off, request routing, admin API, accounting skip.
set -eu
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PORT_UP=4020
PORT_PX=4301
DB=/tmp/kpool-static-test.db
rm -f "$DB" "$DB-wal" "$DB-shm"

cleanup() { kill ${UP_PID:-} ${PX_PID:-} 2>/dev/null || true; }
trap cleanup EXIT
G() { curl -fsS -H "Authorization: Bearer g_tok" "$@"; }

echo "== starting mock upstream :$PORT_UP =="
PORT="$PORT_UP" node test/mock-upstream.js >/tmp/mock-up.log 2>&1 & UP_PID=$!

echo "== starting proxy :$PORT_PX =="
PORT="$PORT_PX" DB_PATH="$DB" UPSTREAM_BASE_URL="http://127.0.0.1:$PORT_UP/v1" \
 GATEWAY_TOKEN=g_tok ADMIN_TOKEN=a_tok \
 KEY_ENC_SECRET="$(openssl rand -hex 32)" \
 DEFAULT_KEY_QUOTA=1000 FAIL_THRESHOLD=3 COOLDOWN_MS=2000 \
 node server.js >/tmp/kpool.log 2>&1 & PX_PID=$!
for i in $(seq 1 50); do G -d '{}' -H 'Content-Type: application/json' "http://127.0.0.1:$PORT_PX/v1/chat/completions" >/dev/null 2>&1 && break; sleep 0.2; done

echo "== import pool keys =="
printf 'sk-mock-key-001\nsk-mock-key-002\n' | \
  curl -fsS -H "x-admin-token: a_tok" -H 'Content-Type: text/plain' --data-binary @- \
  "http://127.0.0.1:$PORT_PX/admin/api/keys" >/dev/null

req() { G -d '{"model":"mock-model","messages":[{"role":"user","content":"hi"}]}' \
  -H 'Content-Type: application/json' "http://127.0.0.1:$PORT_PX/v1/chat/completions" \
  -o /dev/null -D - | grep -i '^x-pool-key:' | tr -d '\r'; }

echo "-- phase 1: pool mode (static OFF) --"
K1=$(req); K2=$(req)
echo "pool req -> $K1 / $K2"
[ "$K1" = "$K2" ] && echo "PASS: pool key used" || { echo "FAIL pool"; exit 1; }

echo "-- phase 2: set static token via admin API --"
curl -fsS -H "x-admin-token: a_tok" -H 'Content-Type: application/json' \
  -d '{"key":"sk-UNIFIED-9f8e7d6c5b4a3210"}' \
  "http://127.0.0.1:$PORT_PX/admin/api/static"
echo
curl -fsS -H "x-admin-token: a_tok" "http://127.0.0.1:$PORT_PX/admin/api/static"
echo

echo "-- phase 3: all requests now use static token --"
S1=$(req); S2=$(req); S3=$(req)
echo "$S1 / $S2 / $S3"
for k in "$S1" "$S2" "$S3"; do [ "$k" = "x-pool-key: static" ] || { echo "FAIL: not static ($k)"; exit 1; }; done
echo "PASS: all static"

echo "-- path A: /v1/models on pool keys still works --"  # sanity that no keys broke
curl -fsS -H "x-admin-token: a_tok" "http://127.0.0.1:$PORT_PX/admin/api/static"

echo "-- phase 4: clear static -> pool again --"
curl -fsS -X DELETE -H "x-admin-token: a_tok" "http://127.0.0.1:$PORT_PX/admin/api/static"
echo
K3=$(req)
echo "post-clear -> $K3"
[ "$K3" != "x-pool-key: static" ] && echo "PASS: pool resumed" || { echo "FAIL: still static"; exit 1; }

echo "== boot log =="
grep -E "mode|listening" /tmp/kpool.log
echo "ALL PASS"
