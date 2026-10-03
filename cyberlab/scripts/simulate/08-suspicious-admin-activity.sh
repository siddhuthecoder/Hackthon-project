#!/bin/bash
# 08-suspicious-admin-activity: one admin performs a burst of role changes
# (>10 in under 5 minutes) via the secure promote endpoint. Original roles
# are restored before the script exits. Should trip RULE-007.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: Suspicious Admin Activity (08)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"

echo ""
log "[1/4] Login as admin@sentinelforge.lab (SUPER_ADMIN)..."
TOKEN=$(login "admin@sentinelforge.lab" "admin_demo_123" "$XFF")
[ -n "$TOKEN" ] || { err "Admin login failed"; exit 1; }
ok "Logged in as SUPER_ADMIN"

USERS_JSON=$(curl -s -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/admin/users")
TARGETS=$(node -e '
  let d = "";
  process.stdin.on("data", c => d += c);
  process.stdin.on("end", () => {
    try {
      const users = JSON.parse(d);
      const targets = users.filter(u => ["USER","STAFF"].includes(u.role)).slice(0, 12);
      process.stdout.write(targets.map(u => u.id + "," + u.role).join(" "));
    } catch (e) { process.stdout.write(""); }
  });
' <<< "$USERS_JSON")

[ -n "$TARGETS" ] || { err "No eligible target users found - run scripts/seed.sh first"; exit 1; }
COUNT=$(echo "$TARGETS" | wc -w)
ok "Selected $COUNT target user(s) to promote"

echo ""
log "[2/4] Promoting $COUNT users to MANAGER via POST /api/admin/users/:id/promote..."
PROMOTED=0
for PAIR in $TARGETS; do
  ID="${PAIR%,*}"
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "X-Forwarded-For: $XFF" \
    -d '{"role":"MANAGER"}' "$API/api/admin/users/$ID/promote")
  [ "$CODE" = "200" ] && PROMOTED=$((PROMOTED + 1))
  echo "  Promoted $ID -> MANAGER (HTTP $CODE)"
done
ok "$PROMOTED/$COUNT promotions succeeded"

echo ""
log "[3/4] Lab cleanup: restoring original roles..."
for PAIR in $TARGETS; do
  ID="${PAIR%,*}"
  ROLE="${PAIR#*,}"
  curl -s -o /dev/null -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "X-Forwarded-For: $XFF" \
    -d "{\"role\":\"${ROLE}\"}" "$API/api/admin/users/$ID/promote"
done
ok "Original roles restored for all $COUNT target user(s)"

echo ""
log "[4/4] Triggering detection..."
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "Suspicious admin activity simulation complete (source IP $XFF)"
