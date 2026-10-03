#!/bin/bash
# scripts/seed.sh - seed the SentinelForge Lab database.
# Runs the compiled seed script inside the running `api` container.
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
. "$DIR/lib.sh"

title "SentinelForge Lab - Seed Script"

wait_for_api 60

log "Seeding database (docker compose exec api node dist/scripts/seed.js)..."
$COMPOSE exec -T api node dist/scripts/seed.js

echo ""
title "Seed complete!"
echo ""
echo "Demo credentials:"
echo "  Super Admin:  admin@sentinelforge.lab / admin_demo_123  (role SUPER_ADMIN)"
echo "  Sample user:  alice.anderson@tenant.alpha.com / demo_password_123  (user-101, role USER)"
echo "  All other seeded users: first.last@tenant.<alpha|beta|gamma>.com / demo_password_123"
echo ""
echo "Tenants: tenant-alpha, tenant-beta, tenant-gamma"
echo "API (host):   http://localhost:3001"
echo "API (nginx):  http://localhost/api"
echo "UI:           http://localhost"
