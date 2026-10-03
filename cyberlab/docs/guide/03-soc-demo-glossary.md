# Beginner Guide - Part 3 of 3: Events, the SOC, simulators, incidents, demo flow, glossary

> Written for: a developer new to cybersecurity. Everything runs only on localhost / Docker.
> Honest note: **SentinelForge (the product) is not built yet.** This lab is its target. Where the demo story
> mentions SentinelForge actions, this guide shows what the **lab does today** and what SentinelForge will do **later**.

---

## 1. Security events

A **security event** is one short record saying "this security-relevant thing just happened." Our API writes one for
every meaningful action, as structured JSON, into MongoDB (`security_events`), onto the Redis channel `security-events`, and
to the API log. Example:

```json
{
  "timestamp": "2026-10-02T18:40:27.000Z",
  "eventType": "AUTH_FAILURE",
  "severity": "medium",
  "userId": null,
  "tenantId": null,
  "sourceIp": "10.77.5.9",
  "endpoint": "/api/auth/login",
  "method": "POST",
  "userAgent": "curl/8.11.0",
  "requestId": "6f0c...",
  "mitreTechnique": "T1110 Brute Force",
  "metadata": { "reason": "invalid_credentials" }
}
```

Field meanings: **eventType** what happened - **severity** low/medium/high/critical - **userId/tenantId** who and which
company - **sourceIp** network address of the caller - **endpoint/method** which URL - **userAgent** which client program
- **requestId** unique id of that request (lets you join events) - **mitreTechnique** the matching entry in the MITRE ATT&CK
catalog (a public encyclopedia of attacker techniques, e.g. T1110 = Brute Force) - **metadata** extra detail.

### Every event type

| Event | What it means | When it happens in the lab | Why the SOC cares | Example |
|---|---|---|---|---|
| `AUTH_SUCCESS` | A login (or registration) succeeded | Correct password at `/auth/login` | A success right after many failures means a guess worked | alice logs in |
| `AUTH_FAILURE` | A login failed | Wrong password / unknown email | Many in a row = brute force | 15 wrong guesses |
| `PASSWORD_RESET` | A reset was requested or done | `forgot-password`, `reset-password` | Attackers reset passwords to take accounts | reset for admin@... |
| `SESSION_CREATED` | A login session started | After a successful login | Shows which IP/device got a session | session from 10.77.5.9 |
| `SESSION_REVOKED` | A session was ended | `logout` | Confirms containment (killing an attacker session) | user logs out |
| `API_REQUEST` | An authenticated API call happened | Every logged-in call (except `/api/security/*`, `/health`) | Volume per user reveals abuse/automation | `GET /api/orders` x70 in a minute |
| `API_ERROR` | The server crashed (HTTP 5xx) | Any 500 response | Errors can hint at probing or injection | invalid input breaks a route |
| `AUTHORIZATION_FAILURE` | Someone was blocked, or reached something they shouldn't | Secure endpoints denying; vulnerable admin routes used by a low role | Repeated denials = someone testing boundaries | USER hits admin route |
| `PRIVILEGE_CHANGE` | A user's role/tenant changed | Mass assignment, promote | Privilege escalation signal | STAFF -> TENANT_ADMIN |
| `ADMIN_ACTION` | An admin-level action ran | Deactivating a user, vulnerable JWT admin call | Admin power is high-risk | user deactivated |
| `DATA_ACCESS` | A record was read | Reading a user or order | Many distinct IDs by one person = enumeration | read `user-102` |
| `BULK_DATA_ACCESS` | A lot of records at once | Orders list with 100+ rows, or export | Typical data theft pattern | export of 67 orders |
| `CROSS_TENANT_ACCESS_ATTEMPT` | A user touched another tenant's data | Reading an order of another tenant | Critical for SaaS: a wall was crossed | Alpha user reads `order-2` |
| `FILE_UPLOAD` | A file was uploaded | `/files/upload*` | Uploads can carry malicious content | `page.html` uploaded |
| `FILE_DOWNLOAD` | A file was downloaded | `/files/download*` | Traversal outside the public folder | `../internal-demo.txt` |
| `SUSPICIOUS_REQUEST` | Input that looks like an attack | SSRF fetch, shell characters in ping, HTML in comments, rejected secure inputs | Early warning of probing | `localhost; whoami` |
| `RATE_LIMIT_TRIGGERED` | The (weak) limiter finally blocked someone | 100+ failures in 5 min from one IP | Shows an attack at scale | HTTP 429 |
| `PAYMENT_CREATED` | An order/payment was created | `POST /api/orders` | Starts a money workflow | new order |
| `PAYMENT_UPDATED` | A payment/status changed | `POST /api/payments` | Tampering shows here | paid 0.01 of 49.99 |
| `REFUND_CREATED` | A refund was issued | `POST /api/refunds` | Refund abuse is common fraud | refund of order |
| `SECURITY_FINDING_TRIGGERED` | The SOC itself opened an incident | Created by the rules engine | Links the incident back into the event stream | "Possible IDOR Attack" |

Extra types defined for future use: `DATA_EXPORT` (emitted by `/orders/export`), `SUSPICIOUS_ACTIVITY`, `CROSS_RESOURCE_ACCESS`.

---

## 2. Audit logs

An **audit log** is a permanent, human-readable record of **who changed what, when**. Security events describe *activity*;
audit logs describe *changes to the business* and are used for accountability and investigations.

```json
{ "actor": "user-001", "actorName": "admin@sentinelforge.lab", "action": "ROLE_CHANGED",
  "target": "user-112", "targetName": "Tom Taylor", "oldValue": "STAFF", "newValue": "MANAGER",
  "tenantId": "tenant-alpha", "timestamp": "2026-10-02T18:40:27Z" }
```
Why it matters: after an incident you need to answer "did the attacker change anything, and what?" Audit logs also deter
insider misuse. Our audit actions include `LOGIN`, `ROLE_CHANGED`, `USER_UPDATED`, `ORDER_UPDATED`, `PAYMENT_UPDATED`, `DATA_EXPORT`.
View them at `/audit-logs`.

---

## 3. The SOC and its detection rules

A **SOC (Security Operations Center)** watches security events, spots dangerous patterns, and responds.
Ours is a **rules engine** inside the lab: every 30 seconds (and immediately when you click a simulator) it reads the last
5 minutes of events and applies rules. A matching pattern creates an **incident**.

| Rule | Detects | Normal behavior | Suspicious behavior |
|---|---|---|---|
| RULE-001 | **Brute force** | A person mistypes a password once or twice | >10 failed logins from one IP within 5 min |
| RULE-002 | **Account takeover** | Login succeeds on the first/second try | A success **after** >5 failures from the same IP |
| RULE-003 | **IDOR behavior** | A user reads their own profile | One user reads >10 *different* user IDs rapidly |
| RULE-004 | **Cross-tenant access** | Users only touch their own tenant | Any read of another tenant's order |
| RULE-005 | **Privilege escalation** | Admins promote people | A STAFF/USER account ends up with an admin role |
| RULE-006 | **Data exfiltration** | Normal list pages of a few rows | Repeated bulk reads / exports (>=100 records or >=3 bulk events) |
| RULE-007 | Suspicious admin activity | An admin edits a user or two | >10 privilege changes by one admin within 5 min |
| RULE-008 | API abuse | A UI makes a few calls | >60 API requests in a minute from one user |
| RULE-009 | Payment tampering | Paid amount equals order total | Payment with client-chosen status/amount |

Rules group by **user + IP**, so two different attack runs do not hide each other. Incidents are de-duplicated for 10 minutes.

**Data exfiltration** = copying data out of a system. In our lab it stays a local response; nothing leaves your machine.

---

## 4. The attack simulators

Folder `scripts/simulate/`. Every script talks only to `http://localhost:3001`, uses fake accounts, and uses a fresh fake
source IP `10.77.x.x` so you can tell runs apart. The UI buttons call the same logic via `POST /api/security/simulate/:id`
(the API attacks *itself* over loopback).

| # | Script | What it simulates / why | What happens in the app | Events generated | SOC detects | SentinelForge should show |
|---|---|---|---|---|---|---|
| 01 | `01-bruteforce` | Password guessing, then a lucky success | 15 failed logins then one good login | 15x `AUTH_FAILURE`, `AUTH_SUCCESS`, `SESSION_CREATED` | RULE-001 (+ RULE-002) | "Brute Force Attack Detected", links to VULN-009 |
| 02 | `02-account-takeover` | Someone gets into Alice's account | 8 failures, success, then reads `/me` and orders | `AUTH_FAILURE`x8, `AUTH_SUCCESS`, `API_REQUEST`x2 | RULE-002 | "Possible Account Takeover" (critical) |
| 03 | `03-idor` | Walking through other users' IDs | Alice reads `user-102 ... user-113` | `DATA_ACCESS`x13 (high) | RULE-003 | "Possible IDOR Attack" -> VULN-001 |
| 04 | `04-cross-tenant-access` | Alpha user reads Beta and Gamma orders | Reads `order-1` (own) then `order-2`, `order-3` | `DATA_ACCESS`, `CROSS_TENANT_ACCESS_ATTEMPT`x2 (critical) | RULE-004 | "Cross-Tenant Data Access Attempt" -> VULN-002 |
| 05 | `05-privilege-escalation` | STAFF gives themselves admin | Mass-assignment PATCH `role=TENANT_ADMIN`, then admin API | `PRIVILEGE_CHANGE` (critical), `API_REQUEST`s | RULE-005 | "Privilege Escalation via Mass Assignment" -> VULN-011 (role is restored afterwards) |
| 06 | `06-api-abuse` | Automated hammering of the API | 70 quick `GET /api/orders` | 70x `API_REQUEST` | RULE-008 | "API Abuse - Excessive Request Rate" |
| 07 | `07-data-exfiltration-simulation` | Pulling lots of data | User reads, big orders list, 3 exports | `DATA_ACCESS`, `BULK_DATA_ACCESS`, `DATA_EXPORT`x3 | RULE-006 | "Possible Data Exfiltration" (data never leaves the machine) |
| 08 | `08-suspicious-admin-activity` | Admin doing a burst of role changes | Promotes 12 users to MANAGER | `PRIVILEGE_CHANGE`x12 | RULE-007 | "Suspicious Admin Activity" (roles restored afterwards) |
| 09 | `09-business-logic-abuse` | Cheating the payment flow | Create order, pay 0.01 with `orderStatus=paid` | `PAYMENT_CREATED`, `PAYMENT_UPDATED` (high) | RULE-009 | "Payment Business Logic Abuse" -> VULN-012 |

Run one: `./scripts/simulate/03-idor.sh`. Each ends with the new incidents list.

---

## 5. Incidents

An **incident** = a group of related suspicious events that the SOC considers a real security problem.

| Field | Meaning |
|---|---|
| `id` | Unique name, e.g. `INC-3f9a1c2b` |
| `title` | Human summary, e.g. "Possible IDOR Attack" |
| `severity` | low / medium / high / critical - how bad |
| `status` | Where it is in handling (below) |
| `detectedAt` | When the SOC noticed |
| `sourceIp` | Network address the activity came from |
| `users` | Accounts involved |
| `assets` | What was touched (endpoints, data) |
| `eventIds` (events) | Evidence: the exact security events |
| `findings` | Related vulnerabilities, e.g. `VULN-001` - **this is the correlation link** |
| `attackPath` | The story of steps, e.g. Authenticate -> Change ID -> Read other user |
| `confidence` | 0-1: how sure the SOC is it is a real attack |
| `recommendedActions` | Suggested response, e.g. "Revoke session", "Patch order authorization" |
| `mitreTactic` / `mitreTechnique` | MITRE ATT&CK classification |

Statuses:
- **OPEN** - just raised, nobody has looked.
- **INVESTIGATING** - someone/something is analyzing it.
- **CONTAINED** - the attacker's access is stopped (sessions revoked, IP blocked) but cleanup continues.
- **RESOLVED** - fixed and closed.
- **FALSE_POSITIVE** - it was harmless activity wrongly flagged. (A **false positive** is a false alarm.)

Change status on the `/incidents` page (expand a row).

---

## 6. The attack graph

An **attack graph** draws an attack as connected **nodes** (things) and **edges** (relationships).

Nodes: `USER`, `IP`, `DEVICE`, `API`, `ENDPOINT`, `VULNERABILITY`, `ASSET`, `DATABASE`, `TENANT`.
Edges: `ACCESSED`, `AUTHENTICATED`, `EXPLOITED`, `TARGETED`, `BELONGS_TO`, `ESCALATED_TO`, `ACCESSES`.

Seeded example (the full chain SentinelForge should discover):

```
 Credential Compromise (IP 172.20.0.5)
        |  AUTHENTICATED
        v
 Authenticated User (user-101, Alice)
        |  EXPLOITED
        v
 IDOR (VULN-001)  ---ACCESSES--->  MongoDB users
        |
 Cross-Tenant Access (VULN-002)  ---TARGETED--->  Tenant Beta ---BELONGS_TO---> Customer data
        |  ESCALATED_TO
        v
 Admin API (VULN-003)  ---ACCESSED---> /api/admin/users/vulnerable
        |  ACCESSES
        v
 Bulk Data Access  (GET /api/orders/export)
```
Why it is useful: single events look boring; the **graph shows how small steps chain into a breach** and which fix breaks the
chain at the cheapest point. New attacks add IP/user/vulnerability nodes to the same graph automatically. See it at `/security-lab/attack-graph`.

---

## 7. Security findings

A **finding** is one reported weakness (what a scanner outputs). Example:

```json
{ "id": "VULN-001", "type": "IDOR/BOLA", "title": "Broken Object Level Authorization",
  "severity": "high", "endpoint": "/api/users/:userId", "method": "GET", "status": "OPEN",
  "cwe": "CWE-639", "owasp": "API1:2023",
  "mitreTactic": "Initial Access", "mitreTechnique": "T1078 Valid Accounts" }
```

| Field | Meaning |
|---|---|
| `id` | Finding name, VULN-001...014 |
| `type` / `title` | Category and plain title |
| `severity` | How serious (low/medium/high/critical) |
| `endpoint` | Where the problem lives |
| `status` | `OPEN` -> `REMEDIATED` -> `VERIFIED` |
| **CWE** | *Common Weakness Enumeration*: a public catalog of weakness **types**; CWE-639 = "authorization bypass through user-controlled key" |
| **OWASP** | *Open Worldwide Application Security Project*: publishes the famous "Top 10" lists. `API1:2023` = #1 in the OWASP **API** Security Top 10 (Broken Object Level Authorization) |
| `secureEndpoint` / `vulnerableEndpoint` | The fixed and broken versions - used for before/after |

API: `GET /api/security/findings` and `/api/security/findings/VULN-001`. Page: `/security-lab`.

---

## 8. The web pages

Open `http://localhost`. (The UI logs in automatically as the demo admin so you can focus on the story.)

| Page | Shows | Why it exists | What a judge should understand |
|---|---|---|---|
| `/dashboard` | Totals, 24h event chart, severity chart, latest events, open incidents (refreshes every 5s) | One-glance health of the lab | "It is live, not a mock." |
| `/users` | All users, roles, tenants | See who exists and their roles | Roles drive every authorization decision |
| `/tenants` | The three tenants with counts | Show multi-tenancy | The isolation boundary that VULN-002 breaks |
| `/products` | Product catalog by tenant | Normal business data | A realistic app, not a toy |
| `/orders` | Orders by tenant | Business data targeted by attacks | What attackers want |
| `/admin` | Admin user management (promote, deactivate) | Where privileged actions happen | Powerful actions are logged as events + audit logs |
| `/security-events` | Live event stream, filterable | Raw telemetry | What the SOC sees |
| `/audit-logs` | Who changed what | Accountability | Evidence trail |
| `/incidents` | Detected incidents; change status | The SOC's output | Detection actually works |
| `/security-lab` | The 14 vulnerabilities with CWE/OWASP/MITRE | The catalog of planted weaknesses | The findings a scanner reports |
| `/security-lab/attacks` | One button per attack simulation | Trigger real attacks safely | Click -> events -> incident, end to end |
| `/security-lab/attack-graph` | Attack chain as a graph | Visualize an attack path | Context beyond single events |
| `/security-lab/xss-demo` | Comments rendered unsafely vs safely | Visual proof of stored XSS | Harmless script really runs |

### What happens when you click "Simulate IDOR"

1. The browser calls `POST /api/security/simulate/03-idor` (same machine).
2. The API logs in as Alice and calls the vulnerable user endpoint 13 times with different IDs.
3. Each call returns another user's data (the vulnerability) and writes a `DATA_ACCESS` event.
4. The detection engine runs, RULE-003 matches.
5. An incident "Possible IDOR Attack" (links to VULN-001) is created, a `SECURITY_FINDING_TRIGGERED` event is logged, the attack graph gets new nodes.
6. The page shows the real steps, number of events and the incident; the dashboard updates within ~5 seconds; the worker adds a notification.

---

## 9. The complete demo flow (21 steps, beginner version)

Legend: **Lab today** = works now. **SentinelForge later** = future product; the lab gives it everything it needs.

| Step | Story | What you do now (lab) | SentinelForge later |
|---|---|---|---|
| 1 | Start the lab | `docker compose up -d --build` then `./scripts/seed.sh`; open `http://localhost` | - |
| 2 | Log in normally | Log in as Alice via `POST /api/auth/login` (UI auto-logs in as admin) | - |
| 3 | Show normal behavior | Alice reads her own profile `/api/users/user-101`, sees her tenant's orders | - |
| 4 | Run a vulnerability scan | Stand-in: `GET /api/security/findings` returns the known list | Scanner tests endpoints and *discovers* the weaknesses |
| 5 | Show discovered vulnerabilities | Open `/security-lab` (14 findings) | Reports them with evidence |
| 6 | Pick IDOR | Choose VULN-001 | Prioritizes it |
| 7 | Reproduce locally | `curl .../api/users/user-102` as Alice (see VULN-001) | Auto-generates the safe reproduction |
| 8 | Run the app normally | Lab is running; users behave normally | - |
| 9 | Run the IDOR simulator | `./scripts/simulate/03-idor.sh` or the "Simulate IDOR" button | Triggers/observes it |
| 10 | Show security events | `/security-events` or `GET /api/security/events` | Ingests the event stream (also on Redis `security-events`) |
| 11 | SOC detection | RULE-003 fires | Its own detection + correlation |
| 12 | Incident created | `/incidents` shows "Possible IDOR Attack" | Same, enriched |
| 13 | AI investigation | (not in lab) | AI reads events, users, IPs, timeline |
| 14 | Correlate with the IDOR finding | Incident `findings: ["VULN-001"]` already links them | AI explains: "this attack used that weakness" |
| 15 | Show the attack graph | `/security-lab/attack-graph` | Builds the graph automatically |
| 16 | Generate remediation | (not in lab) - the secure code pattern is `GET /api/users/secure/:id` | AI proposes the code change |
| 17 | Apply the fix | Lab stand-in: use the **secure twin** `/api/users/secure/:id` | Applies the patch to the real code |
| 18 | Run the same attack again | Same walk of user IDs, against the secure endpoint | Replays the exact attack |
| 19 | Show it is blocked | Responses are **403**; `AUTHORIZATION_FAILURE` events appear | Confirms blocking |
| 20 | Run security verification | `./tests/run.sh` includes secure-vs-vulnerable checks (77 tests) | Runs its verification suite |
| 21 | Final result | Vulnerability **FIXED**, Attack **BLOCKED**, Verification **PASSED** | Shows the three green badges |

Try steps 17-19 right now:
```bash
for i in 102 103 104; do
  curl -s -o /dev/null -w "user-$i vulnerable: %{http_code}   " $API/api/users/user-$i -H "Authorization: Bearer $ALICE"
  curl -s -o /dev/null -w "secure: %{http_code}\n"              $API/api/users/secure/user-$i -H "Authorization: Bearer $ALICE"
done
# vulnerable: 200 (data leaked)     secure: 403 (blocked)
```

---

## 10. Lab vs SentinelForge

| The Lab | SentinelForge |
|---|---|
| A vulnerable application | A security platform |
| Contains **intentional** weaknesses | **Finds** weaknesses |
| Generates security events | Monitors and analyzes events |
| Provides attack simulators | Detects attacks |
| Provides test data and "secure twins" | Investigates incidents, proposes and verifies fixes |
| Used for **testing** | Used for **protection** |

The lab is the exam; SentinelForge is the student taking it.

---

## 11. Why this is strong for a hackathon

Most security demos show only a **scanner list**. This lab lets you show the **whole story**:

```
Discover -> Reproduce -> Attack -> Detect -> Investigate -> Correlate -> Visualize -> Fix -> Verify
```
Judges see: a real weakness, real attack traffic, real alerts, the link between the alert and the weakness, the fix, and proof
that the same attack now fails. Closed-loop proof is far more convincing than "we found 14 issues."

---

## 12. Glossary

| Term | Simple meaning | Example |
|---|---|---|
| Cybersecurity | Protecting systems and data from misuse | Locking an API behind login |
| Vulnerability | A weakness that could be abused | An endpoint that skips an ownership check |
| Exploit | The specific trick that uses a vulnerability | Changing `user-101` to `user-102` |
| Attack | The use of an exploit | Reading everyone's profiles |
| Attacker | Who/what performs the attack | Our simulator script |
| Pentest | Authorized test attack to find weaknesses | A consultant probing your own app |
| AppSec | Security of application code and logic | Reviewing authorization checks |
| SOC | Team/system watching for attacks | The incidents page |
| SIEM | Tool that collects logs and raises alerts | Our events + rules engine, in miniature |
| Authentication | Proving who you are | Email + password |
| Authorization | Deciding what you may do | USER cannot call admin routes |
| RBAC | Permissions by role | STAFF vs TENANT_ADMIN |
| IDOR | Accessing others' objects by changing an ID | `/users/102` |
| BOLA | The API-security name for IDOR | OWASP API1 |
| SSRF | Tricking the server into making a request | Fetching `internal-service` |
| XSS | Browser runs attacker-supplied script | `<img onerror=...>` in a comment |
| NoSQL Injection | Input changes a database query's structure | password `{"$ne":null}` |
| Path Traversal | `../` escapes the intended folder | `../internal-demo.txt` |
| Command Injection | Input adds OS commands | `localhost; whoami` (simulated) |
| Brute Force | Trying many passwords | 15 wrong guesses |
| Account Takeover | Attacker controls someone's account | Guess then log in as Alice |
| Privilege Escalation | Gaining more rights than allowed | STAFF becomes TENANT_ADMIN |
| Data Exfiltration | Copying data out | Bulk export of orders |
| Tenant | One customer organization in a shared app | tenant-alpha |
| Multi-tenancy | Many tenants, one app | Alpha, Beta, Gamma |
| JWT | Signed login token with claims | `Authorization: Bearer eyJ...` |
| Session | A recorded login | A row in `sessions` |
| Security Event | One logged security fact | `AUTH_FAILURE` |
| Audit Log | Record of who changed what | STAFF -> MANAGER by admin |
| Incident | Detected, grouped suspicious activity | "Possible IDOR Attack" |
| Finding | A reported weakness | VULN-001 |
| Attack Path | Steps from entry to goal | Login -> IDOR -> other tenant -> bulk data |
| Attack Graph | Diagram of the attack path | `/security-lab/attack-graph` |
| CVE | Public ID for a known vulnerability in a product | Known flaws in an old library |
| CWE | Catalog of weakness types | CWE-639 |
| OWASP | Non-profit publishing security Top 10 lists | API1:2023 |
| Remediation | Fixing the weakness | Add an ownership check |
| Threat Detection | Spotting attacks from behavior | RULE-001 |
| Correlation | Linking events/findings into one story | Incident -> VULN-001 |
| False Positive | A false alarm | Admin legitimately promoting users |

---

## 13. One-page summary

**What is this project?** A safe, local, deliberately vulnerable business web app (the *lab*) used as a practice target
for a future security product called SentinelForge.

**What is the problem?** Security tools are hard to prove. You need a real weakness, real attack traffic, real alerts and a
real fix to show a tool works - and you cannot attack real companies.

**How does the lab work?** Seven Docker containers (website, API, database, event bus, background worker, front-door proxy, private
service). Data is fake. Every important action writes a security event. A small rules engine turns suspicious events into incidents.

**What are the vulnerabilities?** 14 planted flaws: IDOR, cross-tenant access, broken RBAC, NoSQL injection, stored XSS, SSRF, path
traversal, command injection (simulated), weak rate limiting, JWT authorization, mass assignment, payment logic, insecure upload,
fake secrets - plus one outdated library. Each has a secure twin.

**How do I reproduce them?** Log in as Alice, then call the vulnerable endpoint (Part 2 has each `curl`). Or click a button on
`/security-lab/attacks`, or run `./scripts/simulate/0X-*.sh`.

**What does SentinelForge do?** It finds weaknesses, simulates attacks, watches events, investigates incidents, connects incidents to the
weaknesses they used, proposes and applies fixes, and verifies the fix. (Not built yet.)

**What does the SOC do?** Watches events and raises incidents when patterns match (brute force, takeover, IDOR, cross-tenant, escalation, exfiltration...).

**What does AI do?** It will read the evidence, explain what happened, link the incident to the vulnerability, draw the attack path, write the fix
and confirm the attack is blocked afterward.

**Why do we need the lab?** It is a safe target that makes every step of the story demonstrable and repeatable.

**What do we show judges?** `Vulnerability -> Attack -> Detection -> Incident -> Investigation -> Fix -> Verified`, with real data and real blocking,
not slides.

**Safety reminder:** everything is local, fake and sandboxed: no real credentials, no real payments, no external targets, no cloud
metadata, no real command execution.
