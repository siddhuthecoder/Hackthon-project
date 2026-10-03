#!/bin/bash
# 01-bruteforce: >10 failed logins from one IP, then one successful login.
# Exercises VULN-009 (weak rate limiting, keyed on spoofable X-Forwarded-For)
# and should trip RULE-001 (Brute Force Detection).
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: Brute Force (01)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"

echo ""
log "[1/3] Sending 20 failed login attempts from $XFF..."
FAILED=0
for i in $(seq 1 20); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/api/auth/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $XFF" \
    -d "{\"email\":\"nonexistent@attacker.com\",\"password\":\"wrong${i}\"}")
  [ "$CODE" = "401" ] && FAILED=$((FAILED + 1))
done
ok "$FAILED/20 attempts rejected with HTTP 401 (VULN-009: still well under the weak 100/5min threshold)"

echo ""
log "[2/3] Sending a successful login as alice.anderson@tenant.alpha.com..."
TOKEN=$(login "alice.anderson@tenant.alpha.com" "demo_password_123" "$XFF")
if [ -n "$TOKEN" ]; then ok "Login succeeded, access token issued"; else warn "Login did not return a token"; fi

echo ""
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "Brute force simulation complete (source IP $XFF)"
