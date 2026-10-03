#!/bin/bash
# 06-api-abuse: 70 rapid authenticated requests from one user in under a minute.
# Should trip RULE-008 (API Abuse Detection, >60 requests/user/minute).
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: API Abuse (06)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"

echo ""
log "[1/2] Login as alice.anderson@tenant.alpha.com..."
TOKEN=$(login "alice.anderson@tenant.alpha.com" "demo_password_123" "$XFF")
[ -n "$TOKEN" ] || { err "Login failed"; exit 1; }
ok "Logged in"

echo ""
log "[2/2] Sending 70 rapid GET /api/orders requests (no per-user throttling)..."
SUCCESS=0
for i in $(seq 1 70); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/orders")
  [ "$CODE" = "200" ] && SUCCESS=$((SUCCESS + 1))
done
ok "$SUCCESS/70 requests served with HTTP 200 (no throttling applied)"

echo ""
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "API abuse simulation complete (source IP $XFF)"
