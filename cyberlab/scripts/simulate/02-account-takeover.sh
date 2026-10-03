#!/bin/bash
# 02-account-takeover: multiple failed logins against one account, then a successful
# login and access to sensitive endpoints. Should trip RULE-002 (Account Takeover).
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: Account Takeover (02)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"
TARGET_EMAIL="alice.anderson@tenant.alpha.com"

echo ""
log "[1/4] 8 failed logins against $TARGET_EMAIL..."
for i in $(seq 1 8); do
  curl -s -o /dev/null -X POST "$API/api/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $XFF" \
    -d "{\"email\":\"${TARGET_EMAIL}\",\"password\":\"wrong${i}\"}"
done
ok "8 failed attempts sent"

echo ""
log "[2/4] Successful login (attacker guessed the real password)..."
TOKEN=$(login "$TARGET_EMAIL" "demo_password_123" "$XFF")
[ -n "$TOKEN" ] && ok "Login succeeded, session created" || warn "Login failed"

echo ""
log "[3/4] Accessing sensitive endpoints as the takeover victim..."
ME=$(curl -s -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/auth/me")
ok "GET /api/auth/me -> $(json_get "$ME" "email")"
ORDERS=$(curl -s -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/orders")
ok "GET /api/orders -> response received"

echo ""
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "Account takeover simulation complete (source IP $XFF)"
