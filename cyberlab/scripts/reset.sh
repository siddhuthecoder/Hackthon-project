#!/bin/bash
# scripts/reset.sh - wipe the SentinelForge Lab database.
# Runs the compiled reset script inside the running `api` container.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/lib.sh"

title "SentinelForge Lab - Reset Script"

wait_for_api 60

log "Resetting database (docker compose exec api node dist/scripts/reset.js)..."
$COMPOSE exec -T api node dist/scripts/reset.js

echo ""
title "Reset complete! Run ./scripts/seed.sh to repopulate."
echo ""
echo "Credentials that ./scripts/seed.sh will recreate:"
echo "  Super Admin:  admin@sentinelforge.lab / admin_demo_123  (role SUPER_ADMIN)"
echo "  Sample user:  alice.anderson@tenant.alpha.com / demo_password_123  (user-101, role USER)"
echo "  All other seeded users: first.last@tenant.<alpha|beta|gamma>.com / demo_password_123"
