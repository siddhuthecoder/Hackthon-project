# SentinelForge Lab — Hackathon Demo Script

The exact 18-step story: stand up the vulnerable app, scan it, let the SOC catch
a real attack, then fix it and prove the fix works.

Every command below is copy-pasteable. Set the API base URL once:

```bash
export API=http://localhost:3001     # direct
# export API=http://localhost/api    # through nginx
```

`node` is used instead of `jq` for JSON parsing so the demo has no extra
dependencies. If you have `jq`, substitute freely.

---

## Prerequisites

```bash
cd /d/cyberlab            # or your clone path
docker compose up -d
./scripts/seed.sh
curl -s $API/api/security/demo-status
```

Expected: `{"vulnerabilityCount":14,"tenantCount":3,"userCount":30,...,"status":"operational"}`

Demo credentials (all fake, all local):

| Role | Email | Password |
|---|---|---|
| SUPER_ADMIN | `admin@sentinelforge.lab` | `admin_demo_123` |
| USER (alice, tenant-alpha) | `alice.anderson@tenant.alpha.com` | `demo_password_123` |
| every other seeded user | `first.last@tenant.<alpha\|beta\|gamma>.com` | `demo_password_123` |

> ⚠️ **Safety:** every attack in this script targets `localhost` Docker services
> only. SSRF and path-traversal routes carry a `LAB_SAFETY_GUARD` that refuses
> hosts outside the lab network and paths outside `demo-files/`. The command
> injection endpoint is a simulator — it never executes a shell.

---

## Step 1 — Start the vulnerable application

```bash
docker compose up -d
./scripts/seed.sh
docker compose ps
```

Open <http://localhost>. The SentinelForge Lab dashboard loads against a fully
seeded, deliberately vulnerable API.

## Step 2 — Run a SentinelForge-compatible scan

The lab exposes its own machine-readable finding catalog so any scanner (or
SentinelForge itself) can ingest it without a custom integration:

```bash
curl -s $API/api/security/findings > findings.json
node -e "const f=require('./findings.json');console.log(f.length+' findings');for(const v of f)console.log([v.id,v.severity,v.type,v.cwe,v.owasp,v.mitreTechnique].join(' | '))"
```

```text
14 findings
VULN-001 | high | IDOR/BOLA | CWE-639 | API1:2023 | T1078 Valid Accounts
VULN-002 | critical | Cross-Tenant Access | CWE-639 | API1:2023 | T1530 Data from Cloud Storage
...
```

Three more machine-readable feeds make the lab scanner-friendly:

```bash
curl -s $API/api/security/detection-rules   # 9 SOC rules
curl -s $API/api/security/scenarios        # 9 attack scenarios
curl -s $API/api/security/demo-status      # lab inventory
```

## Step 3 — Show the vulnerability catalog

<http://localhost/security-lab> renders all 14 seeded findings with severity,
CWE / OWASP / MITRE mappings, the attack scenario, and the vulnerable vs. secure
endpoint pair.

Each finding carries the remediation already, for example:

```bash
curl -s $API/api/security/findings/VULN-006
```

```json
{
  "id": "VULN-006",
  "type": "SSRF",
  "severity": "high",
  "endpoint": "/api/fetch-url",
  "secureEndpoint": "/api/fetch-url/secure",
  "vulnerableEndpoint": "/api/fetch-url",
  "cwe": "CWE-918",
  "owasp": "API10:2023",
  "mitreTechnique": "T1046 Network Service Discovery"
}
```

## Step 4 — Focus on the IDOR finding

```bash
curl -s $API/api/security/findings/VULN-001
```

```json
{
  "id": "VULN-001",
  "title": "Broken Object Level Authorization",
  "severity": "high",
  "endpoint": "/api/users/:userId",
  "secureEndpoint": "/api/users/secure/:userId",
  "cwe": "CWE-639",
  "owasp": "API1:2023",
  "mitreTechnique": "T1078 Valid Accounts",
  "attackScenario": "User changes user ID in URL to access another user data"
}
```

## Step 5 — Show the seeded attack graph

```bash
curl -s $API/api/security/attack-graph | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const g=JSON.parse(d);console.log('nodes:',g.nodes.length,'edges:',g.edges.length);for(const e of g.edges)console.log(e.from+' -'+e.type+'-> '+e.to)})"
```

```text
nodes: 10 edges: 10
ip-172.20.0.5 -AUTHENTICATED-> user-101
user-101 -EXPLOITED-> vuln-VULN-001
vuln-VULN-001 -ACCESSES-> db-users
user-101 -EXPLOITED-> vuln-VULN-002
vuln-VULN-002 -TARGETED-> tenant-beta
tenant-beta -BELONGS_TO-> asset-customers
vuln-VULN-002 -ESCALATED_TO-> vuln-VULN-003
vuln-VULN-003 -ACCESSED-> endpoint-admin
endpoint-admin -ACCESSES-> api-orders
api-orders -ACCESSES-> asset-customers
```

Also visible at <http://localhost/security-lab/attack-graph>.

## Step 6 — Switch to normal operation

The app has been running normally the whole time — nothing was exploited yet.
Open <http://localhost/dashboard>: live stat cards, security-event timeline,
vulnerability severity distribution, recent events and active incidents.

Baseline "before" state:

```bash
curl -s $API/api/security/incidents | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const i=JSON.parse(d);console.log(i.length+' incidents');for(const x of i)console.log(x.id,x.status,x.title)})"
```

Three historical incidents only (`INC-seed0001..0003`), nothing live.

## Step 7 — Run the IDOR attack simulation

```bash
./scripts/simulate/03-idor.sh
```

Or from the UI: <http://localhost/security-lab/attacks> → "Simulate" on
**IDOR Enumeration**.

Equivalent by hand:

```bash
TOKEN=$(curl -s -X POST $API/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"alice.anderson@tenant.alpha.com","password":"demo_password_123"}' \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>process.stdout.write(JSON.parse(d).accessToken))")

for id in 101 102 103 104 105 106 107 108 109 110 111 112 113; do
  curl -s -o /dev/null -w "GET /api/users/user-$id -> %{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 10.77.1.1" \
    $API/api/users/user-$id
done
```

```text
GET /api/users/user-101 -> 200   (own record)
GET /api/users/user-102 -> 200   (someone else's record - VULN-001)
...
GET /api/users/user-113 -> 200
```

12 other users' records disclosed. Every request produced a `DATA_ACCESS`
security event tagged `vulnerability: VULN-001`.

## Step 8 — SOC receives the events

```bash
curl -s "$API/api/security/events?eventType=DATA_ACCESS&severity=high&limit=3" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{for(const e of JSON.parse(d))console.log(e.timestamp,e.eventType,e.severity,e.sourceIp,e.userId,e.endpoint,JSON.stringify(e.metadata))})"
```

```text
2026-10-02T10:22:31.114Z DATA_ACCESS high 10.77.1.1 user-101 /api/users/user-113 {"resourceId":"user-113","resourceType":"user","vulnerability":"VULN-001","note":"no_ownership_check"}
...
```

<http://localhost/security-events> shows the same stream in the UI.

## Step 9 — SOC detection engine fires

The background worker evaluates the rules every 30 seconds. To force it now:

```bash
curl -s -X POST $API/api/security/run-detection \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const o=JSON.parse(d);console.log(o.success,o.message);console.log(JSON.stringify(o.results.filter(r=>r.ruleId==='RULE-003')))})"
```

```text
true Detection rules executed
[{"ruleId":"RULE-003","title":"Possible IDOR Attack","sourceIp":"10.77.1.1","created":true}]
```

The full `results` array lists every rule that matched the 5-minute window; the
filter above keeps only the one this demo is about. `RULE-003` matches because
the same user touched **more than 10 distinct user resource IDs within 5
minutes**.

## Step 10 — Incident is created

```bash
curl -s $API/api/security/incidents | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const i=JSON.parse(d)[0];console.log(JSON.stringify(i,null,2))})"
```

```json
{
  "id": "INC-eaafe581",
  "title": "Possible IDOR Attack",
  "severity": "high",
  "status": "OPEN",
  "sourceIp": "10.77.1.1",
  "users": ["user-101"],
  "assets": ["/api/users/:userId"],
  "findings": ["VULN-001"],
  "attackPath": [
    "User Authentication",
    "Access Own Resource",
    "Change Resource ID",
    "Access Another User Data"
  ],
  "confidence": 0.8,
  "recommendedActions": [
    "Audit user access logs",
    "Implement object-level authorization",
    "Review data access patterns"
  ],
  "mitreTactic": "Collection",
  "mitreTechnique": "T1083 File and Directory Discovery"
}
```

Also visible at <http://localhost/incidents>. Move it through the SOC workflow:

```bash
curl -s -X PATCH $API/api/security/incidents/INC-eaafe581 \
  -H 'Content-Type: application/json' -d '{"status":"INVESTIGATING"}'
```

## Step 11 — SentinelForge AI investigates the incident later

This is where the AI layer picks the incident up. Everything it needs is already
in the API — no re-scanning, no log spelunking:

```bash
# 1. the evidence trail behind the incident
curl -s "$API/api/security/events?userId=user-101&limit=20" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const e=JSON.parse(d);console.log(e.length+' events');console.log([...new Set(e.map(x=>x.eventType))].join(', '))})"

# 2. the audit trail for the same actor
curl -s "$API/api/security/audit-logs?limit=20"

# 3. the detection rule that fired
curl -s $API/api/security/detection-rules
```

The analyst narrative the AI produces: *one authenticated tenant-alpha user read
13 distinct user records in under a minute through a single endpoint, with no
ownership check — that is IDOR enumeration, not legitimate profile browsing.*

## Step 12 — AI correlates the incident with the IDOR vulnerability

```bash
curl -s $API/api/security/incidents | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const inc=JSON.parse(d).find(i=>i.findings.includes('VULN-001'));console.log('incident',inc.id,'->',inc.findings.join(','))})"
for v in $(node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>process.stdout.write(JSON.parse(d).find(i=>i.findings.includes('VULN-001')).findings.join(' ')))"); do
  curl -s $API/api/security/findings/$v \
    | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const f=JSON.parse(d);console.log(f.id,f.title,'->',f.vulnerableEndpoint,'| fix:',f.secureEndpoint,'|',f.cwe,f.owasp,f.mitreTechnique)})"
done
```

```text
incident INC-eaafe581 -> VULN-001
VULN-001 Broken Object Level Authorization -> /api/users/:userId | fix: /api/users/secure/:userId | CWE-639 API1:2023 T1078 Valid Accounts
```

The correlation is a join on `incident.findings[] → vulnerability.id`. It
matches three ways at once: the rule's `findings: ['VULN-001']`, the event
metadata `vulnerability: 'VULN-001'`, and the incident's `assets:
['/api/users/:userId']` vs. the finding's `endpoint`.

## Step 13 — Show the complete attack path

```bash
curl -s $API/api/security/attack-graph | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const g=JSON.parse(d);for(const n of g.nodes)console.log(n.type.padEnd(15),n.label)})"
```

```text
IP              172.20.0.5 (credential compromise source)
USER            user-101 (Alice Anderson)
VULNERABILITY   VULN-001: IDOR
VULNERABILITY   VULN-002: Cross-Tenant Access
ENDPOINT        /api/admin/users/vulnerable
VULNERABILITY   VULN-003: Broken RBAC
DATABASE        MongoDB: users collection
TENANT          Tenant Beta
ASSET           Customer Data (Tenant Beta)
API             GET /api/orders/export (bulk data access)
```

Attack path: `Credential Compromise → user-101 → IDOR (VULN-001) → Cross-Tenant
(VULN-002) → Admin API (VULN-003) → Bulk Data Access`. Every node and edge is
reproduced live by `run-detection` in `server/src/services/detectionEngine.ts`.

## Step 14 — Generate the remediation

The remediation for VULN-001 is object-level authorization on every user-data
read:

```text
Fix: enforce req.user.userId === req.params.userId (or an admin role)
     before any database read; return 403 otherwise;
     log AUTHORIZATION_FAILURE with the attempted target id.

Reference implementation already in the repo:
  vulnerable  GET /api/users/:userId        -> server/src/routes/users.ts
  secure      GET /api/users/secure/:userId -> same file, ownership check
```

The API advertises it on the finding itself:

```bash
curl -s $API/api/security/findings/VULN-001 \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const f=JSON.parse(d);console.log('vulnerable:',f.vulnerableEndpoint);console.log('secure    :',f.secureEndpoint)})"
```

## Step 15 — Apply the secure authorization

```bash
# the vulnerable path: still wide open
curl -s -o /dev/null -w "GET /api/users/user-102        -> %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" $API/api/users/user-102

# the hardened path: object-level authorization enforced
curl -s -w "\nGET /api/users/secure/user-102 -> %{http_code}\n" \
  -H "Authorization: Bearer $TOKEN" $API/api/users/secure/user-102
```

```text
GET /api/users/user-102        -> 200
GET /api/users/secure/user-102 -> 403
{"error":"Access denied: you can only view your own profile"}
GET /api/users/secure/user-102 -> 403
```

The denial is recorded as telemetry:

```bash
curl -s "$API/api/security/events?eventType=AUTHORIZATION_FAILURE&limit=1" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const e=JSON.parse(d)[0];console.log(e.eventType,e.severity,e.endpoint,JSON.stringify(e.metadata))})"
```

```text
AUTHORIZATION_FAILURE medium /api/users/secure/user-102 {"reason":"not_owner","targetUser":"user-102"}
```

## Step 16 — Re-run the same attack

```bash
for id in 101 102 103 104 105 106 107 108 109 110 111 112 113; do
  curl -s -o /dev/null -w "GET /api/users/secure/user-$id -> %{http_code}\n" \
    -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 10.77.2.2" \
    $API/api/users/secure/user-$id
done
```

```text
GET /api/users/secure/user-101 -> 200   (own record still allowed)
GET /api/users/secure/user-102 -> 403
GET /api/users/secure/user-103 -> 403
...
```

## Step 17 — The attack is blocked

Nothing to enumerate: 12 of 13 requests denied, and the one 200 is the attacker's
own record. Break down what the SOC actually recorded for the blocked run
(source IP `10.77.2.2`):

```bash
curl -s "$API/api/security/events?sourceIp=10.77.2.2&limit=200" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const e=JSON.parse(d);const by={};for(const x of e)by[x.eventType]=(by[x.eventType]||0)+1;console.log(JSON.stringify(by));console.log('VULN-001 DATA_ACCESS events:',e.filter(x=>x.eventType==='DATA_ACCESS'&&x.metadata&&x.metadata.vulnerability==='VULN-001').length)})"
```

```text
{"API_REQUEST":13,"AUTHORIZATION_FAILURE":12,"DATA_ACCESS":1}
VULN-001 DATA_ACCESS events: 0
```

Compare that with the unpatched run in step 7 — 13 `DATA_ACCESS` events, every one
tagged `VULN-001`. After the fix:

- **No disclosure** — no other user's PII is returned, and zero `DATA_ACCESS`
  events carry the `VULN-001` tag.
- **Full auditability** — 12 `AUTHORIZATION_FAILURE` events, each naming the
  attempted target id.
- **The detector stops seeing an exploitation pattern** — RULE-003 keys on
  `DATA_ACCESS` events over distinct user resource ids. The blocked run produces
  one (the attacker's own record), far below the >10 threshold, so the same
  script no longer produces an IDOR incident:

```bash
curl -s -X POST $API/api/security/run-detection \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const r=JSON.parse(d).results.filter(x=>x.ruleId==='RULE-003');console.log('RULE-003 matches:',r.length,r.map(x=>x.sourceIp+' created='+x.created).join(','))})"
```

```text
RULE-003 matches: 1 10.77.1.1 created=false
```

The one remaining match is the **pre-fix** run from step 7, still inside the
5-minute event window; `created=false` because its incident was already opened
in step 10. The blocked run's IP (`10.77.2.2`) produced no match at all. Wait out
the window (or `./scripts/reset.sh && ./scripts/seed.sh`) and the rule goes
quiet — the fix removed the signal the rule was built on.

## Step 18 — Verification passes

The full before/after proof, in one runnable block:

```bash
echo "--- vulnerable endpoint still reproduces the flaw (VULN-001 open)"
curl -s -o /dev/null -w "  GET /api/users/user-102         -> %{http_code} (expected 200)\n" \
  -H "Authorization: Bearer $TOKEN" $API/api/users/user-102

echo "--- secure endpoint blocks it"
curl -s -o /dev/null -w "  GET /api/users/secure/user-102  -> %{http_code} (expected 403)\n" \
  -H "Authorization: Bearer $TOKEN" $API/api/users/secure/user-102

echo "--- owner can still read their own record"
curl -s -o /dev/null -w "  GET /api/users/secure/user-101  -> %{http_code} (expected 200)\n" \
  -H "Authorization: Bearer $TOKEN" $API/api/users/secure/user-101

echo "--- the attempt is on the audit trail"
curl -s "$API/api/security/events?eventType=AUTHORIZATION_FAILURE&limit=1" \
  | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{const e=JSON.parse(d)[0];console.log('  ',e.eventType,e.endpoint,JSON.stringify(e.metadata))})"

echo "--- e2e suite covering VULN-001..013"
node --test tests/e2e/*.test.mjs
```

```text
--- vulnerable endpoint still reproduces the flaw (VULN-001 open)
  GET /api/users/user-102         -> 200 (expected 200)
--- secure endpoint blocks it
  GET /api/users/secure/user-102  -> 403 (expected 403)
--- owner can still read their own record
  GET /api/users/secure/user-101  -> 200 (expected 200)
--- the attempt is on the audit trail
   AUTHORIZATION_FAILURE /api/users/secure/user-102 {"reason":"not_owner","targetUser":"user-102"}
--- e2e suite covering VULN-001..013
# pass 77
# fail 0
```

---

## After the demo

```bash
./scripts/reset.sh    # wipe every collection
./scripts/seed.sh     # back to a pristine dataset
```

## Running every scenario

```bash
for script in scripts/simulate/*.sh; do
  echo "### $script"
  bash "$script"
done
```

| Script | Scenario | Rule | Incident |
|---|---|---|---|
| `01-bruteforce.sh` | 20 failed logins, then a success | RULE-001 / RULE-002 | Brute Force Attack Detected |
| `02-account-takeover.sh` | 8 failures on one account, then a success | RULE-002 | Possible Account Takeover |
| `03-idor.sh` | user-102..user-113 via `/api/users/:id` | RULE-003 | Possible IDOR Attack |
| `04-cross-tenant-access.sh` | Tenant Beta/Gamma orders from Tenant Alpha | RULE-004 | Cross-Tenant Data Access Attempt |
| `05-privilege-escalation.sh` | STAFF mass-assigns `role: TENANT_ADMIN` | RULE-005 | Privilege Escalation via Mass Assignment |
| `06-api-abuse.sh` | 70 rapid authenticated requests | RULE-008 | API Abuse - Excessive Request Rate |
| `07-data-exfiltration-simulation.sh` | 30 user reads + 3 exports | RULE-006 | Possible Data Exfiltration |
| `08-suspicious-admin-activity.sh` | admin promotes 12 users, then reverts | RULE-007 | Suspicious Admin Activity |
| `09-business-logic-abuse.sh` | order paid with `amount: 0.01` | RULE-009 | Payment Business Logic Abuse |

Each script restores any role it changes, so they are safe to re-run in any
order.