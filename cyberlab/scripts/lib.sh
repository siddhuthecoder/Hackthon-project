#!/bin/bash
# scripts/lib.sh - shared helpers for SentinelForge Lab scripts.
# Source this file: `. "$(dirname "$0")/lib.sh"`
# No external dependencies beyond curl, sed/grep and (optionally) node.

API="${API:-http://localhost:3001}"
COMPOSE="${COMPOSE:-docker compose}"

# ---- colors (no-op if not a tty) ----
if [ -t 1 ]; then
  C_RESET='\033[0m'; C_BOLD='\033[1m'; C_GREEN='\033[32m'; C_RED='\033[31m'; C_YELLOW='\033[33m'; C_CYAN='\033[36m'
else
  C_RESET=''; C_BOLD=''; C_GREEN=''; C_RED=''; C_YELLOW=''; C_CYAN=''
fi

log()  { printf '%b\n' "${C_CYAN}[*]${C_RESET} $*"; }
ok()   { printf '%b\n' "${C_GREEN}[+]${C_RESET} $*"; }
warn() { printf '%b\n' "${C_YELLOW}[!]${C_RESET} $*"; }
err()  { printf '%b\n' "${C_RED}[x]${C_RESET} $*" 1>&2; }
title() {
  printf '%b\n' "${C_BOLD}=========================================${C_RESET}"
  printf '%b\n' "${C_BOLD}  $*${C_RESET}"
  printf '%b\n' "${C_BOLD}=========================================${C_RESET}"
}

# wait_for_api [timeout_seconds] [url]
# Polls the API health endpoint until it responds or the timeout elapses.
wait_for_api() {
  local timeout="${1:-60}"
  local url="${2:-$API/health}"
  local waited=0
  log "Waiting for API at $url (timeout ${timeout}s)..."
  while [ "$waited" -lt "$timeout" ]; do
    if curl -s -o /dev/null -w '%{http_code}' "$url" 2>/dev/null | grep -q '^200$'; then
      ok "API is up (after ${waited}s)"
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  err "API did not become healthy within ${timeout}s at $url"
  return 1
}

# random_xff - prints a pseudo-random 10.77.x.x address for simulation source-IP isolation.
random_xff() {
  echo "10.77.$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1))"
}

# json_get <json> <dotted.path> - tiny JSON field extractor using node (no jq dependency).
# Falls back to empty string if node is unavailable or the path is missing.
json_get() {
  local json="$1"
  local path="$2"
  if command -v node >/dev/null 2>&1; then
    node -e '
      let data = "";
      process.stdin.on("data", d => data += d);
      process.stdin.on("end", () => {
        try {
          const obj = JSON.parse(data);
          const parts = process.argv[1].split(".");
          let cur = obj;
          for (const p of parts) {
            if (cur === null || cur === undefined) break;
            cur = cur[p];
          }
          if (cur === undefined || cur === null) process.stdout.write("");
          else if (typeof cur === "object") process.stdout.write(JSON.stringify(cur));
          else process.stdout.write(String(cur));
        } catch (e) {
          process.stdout.write("");
        }
      });
    ' "$path" <<< "$json"
  else
    # crude grep/sed fallback for a simple top-level string field
    echo "$json" | sed -n "s/.*\"${path##*.}\":\"\([^\"]*\)\".*/\1/p" | head -1
  fi
}

# run_detection [xff] - triggers POST /api/security/run-detection and prints the
# incidents this run is responsible for. Pass the run's X-Forwarded-For so the
# summary lists incidents attributable to that source IP.
run_detection() {
  local xff="${1:-}"
  log "Triggering SOC detection engine (POST /api/security/run-detection)..."
  local resp incidents tmp tmp2
  resp=$(curl -s -X POST "$API/api/security/run-detection")
  incidents=$(curl -s "$API/api/security/incidents")
  tmp="$(mktemp)"
  tmp2="$(mktemp)"
  printf '%s' "$incidents" > "$tmp"
  printf '%s' "$resp" > "$tmp2"

  SIM_XFF="$xff" SIM_INCIDENTS="$tmp" SIM_DETECTION_FILE="$tmp2" node -e '
    const fs = require("fs");
    try {
      const obj = JSON.parse(fs.readFileSync(process.env.SIM_DETECTION_FILE, "utf8"));
      const list = JSON.parse(fs.readFileSync(process.env.SIM_INCIDENTS, "utf8"));
      const created = (obj.results || []).filter(r => r.created);
      const xff = process.env.SIM_XFF || "";
      console.log(`  Rules evaluated, ${created.length} new incident(s) created in this pass:`);
      for (const r of created) console.log(`    - ${r.ruleId}: ${r.title} (sourceIp ${r.sourceIp})`);
      if (created.length === 0) {
        console.log("    (none - already raised by the background worker or still inside the 10 minute dedup window)");
      }
      if (xff) {
        const mine = list.filter(i => i.sourceIp === xff);
        console.log(`  Incidents raised by this run (sourceIp ${xff}):`);
        if (mine.length === 0) {
          console.log("    (none)");
        } else {
          for (const i of mine) {
            console.log(`    [${i.severity.toUpperCase()}] ${i.id} - ${i.title} - status=${i.status} findings=${(i.findings || []).join(",")} confidence=${i.confidence}`);
          }
        }
      }
    } catch (e) {
      console.log("  (could not parse detection response)");
    }
  ' 2>/dev/null || true
  rm -f "$tmp" "$tmp2"
}

# print_newest_incidents <n> - prints the n most recent incidents (GET /api/security/incidents is sorted desc).
print_newest_incidents() {
  local n="${1:-5}"
  log "Newest incidents (GET /api/security/incidents):"
  local resp
  resp=$(curl -s "$API/api/security/incidents")
  if command -v node >/dev/null 2>&1; then
    echo "$resp" | node -e '
      let data = "";
      process.stdin.on("data", d => data += d);
      process.stdin.on("end", () => {
        try {
          const list = JSON.parse(data);
          const n = parseInt(process.argv[1], 10);
          for (const i of list.slice(0, n)) {
            console.log(`  [${i.severity.toUpperCase()}] ${i.id} - ${i.title} - status=${i.status} sourceIp=${i.sourceIp} confidence=${i.confidence}`);
          }
          if (list.length === 0) console.log("  (no incidents found)");
        } catch (e) {
          console.log("  (could not parse incidents response)");
        }
      });
    ' "$n"
  else
    ok "Incidents endpoint responded (install node for a formatted summary)"
  fi
}

# login <email> <password> - prints the accessToken on success (empty on failure).
login() {
  local email="$1"
  local password="$2"
  local xff="$3"
  local resp
  resp=$(curl -s -X POST "$API/api/auth/login" \
    -H "Content-Type: application/json" \
    ${xff:+-H "X-Forwarded-For: $xff"} \
    -d "{\"email\":\"${email}\",\"password\":\"${password}\"}")
  json_get "$resp" "accessToken"
}
