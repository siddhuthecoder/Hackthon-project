#!/bin/bash
# 07-data-exfiltration-simulation: bulk record access plus repeated exports.
# Responses stay local to this script - nothing leaves the lab.
# Should trip RULE-006 (Data Exfiltration Detection).
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: Data Exfiltration (07)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"

echo ""
log "[1/4] Login as alice.anderson@tenant.alpha.com..."
TOKEN=$(login "alice.anderson@tenant.alpha.com" "demo_password_123" "$XFF")
[ -n "$TOKEN" ] || { err "Login failed"; exit 1; }
ok "Logged in"

echo ""
log "[2/4] Reading 30 user records via the vulnerable IDOR endpoint..."
for ID in $(seq 101 130); do
  curl -s -o /dev/null -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/users/user-$ID"
done
ok "30 user records accessed (user-101..user-130)"

echo ""
log "[3/4] Bulk order listing (?limit=1000)..."
LIST=$(curl -s -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/orders?limit=1000")
ok "GET /api/orders?limit=1000 returned a bulk result set"

echo ""
log "[4/4] Exporting orders 3 times (GET /api/orders/export)..."
for i in 1 2 3; do
  RESP=$(curl -s -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/orders/export")
  COUNT=$(json_get "$RESP" "count")
  ok "Export #$i -> $COUNT order records returned (local response only, no external transfer)"
done

echo ""
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "Data exfiltration simulation complete (source IP $XFF)"
