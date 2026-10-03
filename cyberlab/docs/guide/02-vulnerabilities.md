# Beginner Guide - Part 2 of 3: Every vulnerability in the lab

> Written for: a developer new to cybersecurity. All commands target **only** `localhost` (the lab).
> Every vulnerable endpoint has a **secure twin** (`.../secure`) so you can compare before/after.

## 0. Setup used by every example

Start the lab and load data:

```bash
docker compose up -d --build
./scripts/seed.sh
```

Get a login token for Alice (a normal USER in tenant-alpha) and for the admin. A **token** is the
"ticket" the API gives you after login (see Part 1, section 8):

```bash
API=http://localhost:3001
login() { curl -s -X POST $API/api/auth/login -H 'Content-Type: application/json' \
  -d "{\"email\":\"$1\",\"password\":\"$2\"}" | node -pe "JSON.parse(require('fs').readFileSync(0)).accessToken"; }

ALICE=$(login alice.anderson@tenant.alpha.com demo_password_123)   # USER, tenant-alpha, id user-101
ADMIN=$(login admin@sentinelforge.lab admin_demo_123)              # SUPER_ADMIN
```

How to read each section below (the same 9 questions for every vulnerability):
**A** what it is - **B** why dangerous - **C** where in the lab - **D** what a normal user may do -
**E** what the flaw allows - **F** how to reproduce - **G** evidence - **H** secure behavior - **I** how SentinelForge detects it.

A few words used throughout:
- **Endpoint** = one API URL + method, e.g. `GET /api/orders/order-2`.
- **Payload** = the input you send that triggers the weakness.
- **HTTP status** = the answer code: `200` ok, `401` not logged in, `403` forbidden, `404` not found.
- **Evidence** = proof, e.g. a response that contains data you should not have seen, plus the security event the lab logged.

---

## VULN-001 - IDOR / BOLA (reading someone else's record)

- **A. What:** *IDOR (Insecure Direct Object Reference) / BOLA (Broken Object Level Authorization).* The API
  takes an ID from the URL and returns that record **without checking the record belongs to you**.
- **B. Why dangerous:** Anyone logged in can walk through IDs (`user-101`, `user-102`, ...) and download
  everybody's data. It is the most common serious API bug in the real world.
- **C. Where:** `GET /api/users/:userId` (also `/api/users/vulnerable/:userId`).
- **D. Normal user may:** read only **their own** record (`user-101`).
- **E. Flaw allows:** read any user's name, email, role, tenant, phone.
- **F. Reproduce:**
```bash
# Normal: Alice reads herself
curl -s $API/api/users/user-101 -H "Authorization: Bearer $ALICE"

# Attack: Alice changes the ID to someone else
curl -s $API/api/users/user-102 -H "Authorization: Bearer $ALICE"
```
```
NORMAL:  Alice -> /api/users/user-101 -> Alice's data           OK
ATTACK:  Alice -> /api/users/user-102 -> Bob's data  + "warning":"VULNERABLE_ENDPOINT_IDOR"   NOT OK
```
- **G. Evidence:** the second response contains Bob's record; a `DATA_ACCESS` security event (severity high,
  metadata `vulnerability: VULN-001`) appears in `GET /api/security/events`.
- **H. Secure:** `GET /api/users/secure/user-102` as Alice -> **403** "you can only view your own profile",
  and an `AUTHORIZATION_FAILURE` event is logged.
- **I. SentinelForge:** *scan:* request `/api/users/<other id>` with a low-privilege token and see foreign data
  -> finding VULN-001 (CWE-639, OWASP API1:2023). *Runtime:* RULE-003 - one user reads >10 different user IDs in 5 min.

---

## VULN-002 - Cross-tenant data access

- **A. What:** Same idea as IDOR but across **tenant** boundaries. The API returns an order without checking
  that the order belongs to the caller's tenant.
- **B. Why dangerous:** In SaaS this leaks one customer company's data to another company. Business-ending.
- **C. Where:** `GET /api/orders/:orderId` (and `/api/orders/vulnerable/:orderId`).
- **D. Normal user may:** read orders of **their own tenant** only (`order-1`, `order-4`, ... for alpha).
- **E. Flaw allows:** Alpha user reads Beta (`order-2`) or Gamma (`order-3`) orders.
- **F. Reproduce:**
```bash
curl -s $API/api/orders/order-1 -H "Authorization: Bearer $ALICE"   # own tenant (alpha)  -> tenantId tenant-alpha
curl -s $API/api/orders/order-2 -H "Authorization: Bearer $ALICE"   # BETA's order        -> tenantId tenant-beta  (leak)
```
```
Alpha user -> Beta order -> data returned -> DATA LEAKAGE
```
- **G. Evidence:** response has `"tenantId":"tenant-beta"` while Alice is `tenant-alpha`; the lab logs a
  **critical** `CROSS_TENANT_ACCESS_ATTEMPT` event.
- **H. Secure:** `GET /api/orders/secure/order-2` -> **403** "order belongs to different tenant" (`AUTHORIZATION_FAILURE` logged).
- **I. SentinelForge:** scan with two tenants' tokens; runtime RULE-004 fires on **any** cross-tenant event (critical).

---

## VULN-003 - Broken RBAC (a role reaches admin functions)

- **A. What:** *RBAC = Role-Based Access Control.* Admin endpoints exist but the vulnerable ones **do not check the caller's role**.
  Also called BFLA (Broken Function Level Authorization).
- **B. Why dangerous:** A low-privilege user can list all users, promote themselves or delete accounts: **privilege escalation**.
- **C. Where:** `GET /api/admin/users/vulnerable`, `POST /api/admin/users/:id/promote/vulnerable`, `DELETE /api/admin/users/:id/vulnerable`.
- **D. Normal STAFF/USER may:** nothing under `/api/admin`.
- **E. Flaw allows:** anyone who is logged in uses admin functions.
- **F. Reproduce:**
```bash
curl -s $API/api/admin/users            -H "Authorization: Bearer $ALICE"   # secure route -> 403 "Insufficient permissions"
curl -s $API/api/admin/users/vulnerable -H "Authorization: Bearer $ALICE"   # no role check -> list of ALL users (all tenants)
```
```
STAFF/USER -> /api/admin/users            -> 403 (correct)
STAFF/USER -> /api/admin/users/vulnerable -> admin data (wrong)
```
- **G. Evidence:** the second call returns all users incl. other tenants; `AUTHORIZATION_FAILURE` event (high, `vulnerability: VULN-003`).
- **H. Secure:** the same routes **without** `/vulnerable` use `requireRole('SUPER_ADMIN','TENANT_ADMIN')` and also stop tenant admins touching other tenants.
- **I. SentinelForge:** replay admin URLs with a low-role token; any 200 = finding (CWE-285, OWASP API5:2023).

---

## VULN-004 - NoSQL injection (login)

- **A. What:** MongoDB is a **NoSQL** database: queries are JSON objects like `{ email: "...", passwordHash: "..." }`.
  *Injection* means user input is allowed to **change the structure of the query** instead of being treated as plain text.
  In Mongo, a value like `{"$ne": null}` means "not equal to null" - i.e. "matches anything".
- **B. Why dangerous:** An attacker can log in as someone without knowing the password.
- **C. Where:** `POST /api/auth/vulnerable-login`. (Secure twin: `/api/auth/secure-login`.)
- **D. Normal user:** sends two strings, email and password.
- **E. Flaw allows:** sending the password as an *object* so the database query matches the account regardless of the real password.
- **F. Reproduce (local lab only):**
```bash
# Normal login with the real password: works
curl -s -X POST $API/api/auth/vulnerable-login -H 'Content-Type: application/json' \
  -d '{"email":"admin@sentinelforge.lab","password":"admin_demo_123"}'

# Injection: password is an object that means "anything that exists"
curl -s -X POST $API/api/auth/vulnerable-login -H 'Content-Type: application/json' \
  -d '{"email":"admin@sentinelforge.lab","password":{"$ne":null}}'
```
- **G. Evidence:** the second call returns an `accessToken` for SUPER_ADMIN without the password; `AUTH_SUCCESS` (high,
  note `nosql_injection_login`, MITRE T1078) is logged.
- **H. Secure:** `/api/auth/secure-login` rejects non-string inputs with **400** "email and password must be strings" and logs a `SUSPICIOUS_REQUEST`.
  Real systems also validate input types and sanitize operators.
- **I. SentinelForge:** send object-typed credentials; a token coming back = finding (CWE-943, OWASP API3:2023).

---

## VULN-005 - Stored XSS (cross-site scripting)

- **A. What:** *XSS* = a page displays user-supplied text **as HTML/JavaScript** and the browser runs it. *Stored* means the
  text was saved in the database first, so every later viewer is affected.
- **B. Why dangerous:** Real attackers use it to steal sessions, perform actions as the victim, or deface pages. (Our demo only shows a harmless message.)
- **C. Where:** `POST /api/comments` stores raw text; the page `/security-lab/xss-demo` shows comments unescaped for the vulnerable ones.
- **D. Normal user:** posts plain text like "Great router".
- **E. Flaw allows:** posting HTML such as an `<img>` tag whose `onerror` code runs in other people's browsers.
- **F. Reproduce:** open `http://localhost/security-lab/xss-demo`. A seeded comment already shows a red
  "[VULN-005 XSS DEMO: script ran in your browser]" - that text was produced **by the stored payload running**.
  Or via API (harmless payload that only changes the page title):
```bash
curl -s -X POST $API/api/comments -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  -d '{"productId":"prod-1","content":"<img src=x onerror=\"document.title='XSS-OK'\">hello"}'
```
  Reload the xss-demo page: the browser tab title becomes `XSS-OK`. That is code executing.
- **G. Evidence:** the tab title changed / red message appears; a `SUSPICIOUS_REQUEST` (high, `containsMarkup: true`) event is logged.
- **H. Secure:** `POST /api/comments/safe` HTML-escapes the text (`&lt;img ...`), so it is displayed as literal characters.
  Real fix: escape on output, use a templating layer that escapes by default, add a Content-Security-Policy.
- **I. SentinelForge:** inject a harmless marker, load the page, see it parsed as HTML (CWE-79, OWASP A03:2021).

---

## VULN-006 - SSRF (server-side request forgery)

- **A. What:** The server can make HTTP requests (e.g. "fetch this URL for me"). In SSRF the attacker **tricks the server
  into requesting something it should not**, typically an internal service that outsiders cannot reach.
- **B. Why dangerous:** Servers sit **inside** the private network. An SSRF can read internal admin pages or cloud credentials
  (in real life, cloud "metadata" endpoints). The attacker borrows the server's trusted position.
- **C. Where:** `POST /api/fetch-url`. Private target: `internal-service` at `/internal/demo-secret` (only reachable inside Docker).
- **D. Normal user:** supplies a harmless URL to fetch.
- **E. Flaw allows:** pointing the server at the private service and getting its fake secret back.
- **F. Reproduce:**
```bash
# Not reachable from your browser:  http://internal-service:8080  (no such host outside Docker)
curl -s -X POST $API/api/fetch-url -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  -d '{"url":"http://internal-service:8080/internal/demo-secret"}'
```
```
Alice -> API -> (API fetches) -> internal-service -> {"secret":"demo_internal_secret_123"} -> back to Alice
```
- **G. Evidence:** response `data` contains `demo_internal_secret_123`; `SUSPICIOUS_REQUEST` event (`internalTarget: true`).
- **H. Secure:** `/api/fetch-url/secure` only allows an exact allowlist; anything else -> **403** `URL not in allowlist`.
- **Lab safety guard (important):** even the vulnerable endpoint refuses any host that is not a lab host. Trying
  `http://169.254.169.254/...` (cloud metadata) or any outside site returns **403 LAB_SAFETY_GUARD**. The lab can never call the real internet.
- **I. SentinelForge:** supply internal hostnames and see content come back (CWE-918, OWASP API10:2023).

---

## VULN-007 - Path traversal

- **A. What:** A file endpoint takes a file *name* and joins it onto a folder. If it does not block `../` ("go up one folder"),
  the caller can **escape** the intended folder.
- **B. Why dangerous:** Real systems leak config files, keys, source code or `/etc/passwd`.
- **C. Where:** `GET /api/files/download?file=...`. Intended folder: `demo-files/public/`. A private file sits one level up: `demo-files/internal-demo.txt`.
- **D. Normal user:** downloads `public.txt`.
- **E. Flaw allows:** `../internal-demo.txt` reads a file outside the intended folder.
- **F. Reproduce:**
```bash
curl -s "$API/api/files/download?file=public.txt"            -H "Authorization: Bearer $ALICE"   # expected
curl -s "$API/api/files/download?file=../internal-demo.txt"  -H "Authorization: Bearer $ALICE"   # escapes the folder
```
```
expected:  demo-files/public/public.txt
attack:    demo-files/public/../internal-demo.txt  ->  demo-files/internal-demo.txt   (a file you should not get)
```
- **G. Evidence:** response shows `"traversed": true` and the internal demo file text; `FILE_DOWNLOAD` event (high, MITRE T1005).
- **H. Secure:** `/api/files/download/secure` accepts only the plain name `public.txt` (allowlist, no slashes).
- **Lab safety guard:** `?file=../../etc/passwd` is refused with **403 LAB_SAFETY_GUARD**. Only the harmless demo files are ever reachable.
- **I. SentinelForge:** send `../` sequences and look for content that is not in the public set (CWE-22, OWASP A01:2021).

---

## VULN-008 - Command injection (safe simulator)

- **A. What:** An app builds an operating-system command from user input (e.g. `ping -c 1 <host>`). If the input can contain
  shell symbols like `;`, `|`, `&`, an attacker **adds their own commands**.
- **B. Why dangerous:** On a real server this is full takeover.
- **C. Where:** `POST /api/tools/ping`.
- **Safety first:** **our lab never runs any real command.** The endpoint is a *simulator*: it only pretends, using a fixed lookup
  table, and prints `[SIMULATED]` text. No `child_process`, no shell, nothing executes on your machine.
- **D. Normal user:** sends a hostname like `localhost`.
- **E. Flaw (simulated):** input containing `;` etc. is shown as if it were run in a shell.
- **F. Reproduce:**
```bash
curl -s -X POST $API/api/tools/ping -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' -d '{"host":"localhost"}'
curl -s -X POST $API/api/tools/ping -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' -d '{"host":"localhost; whoami"}'
```
  The second shows `[SIMULATED] sh -c "ping -c 1 localhost; whoami"` and `[SIMULATED] sandbox-user`.
- **G. Evidence:** `"injectionDetected": true`; `SUSPICIOUS_REQUEST` event (MITRE T1059).
- **H. Secure:** `/api/tools/ping/secure` only accepts `^[a-zA-Z0-9.-]+$`; real code should avoid shells entirely and pass arguments as an array.
- **I. SentinelForge:** inject metacharacters, look for command-output side effects (CWE-78, OWASP A03:2021).

---

## VULN-009 - Weak login rate limiting

- **A. What:** *Rate limiting* = slowing or blocking someone who tries too many times. Ours is deliberately weak: it only blocks after
  **100 failures in 5 minutes per IP**, and the IP is read from a header the caller controls (`X-Forwarded-For`).
- **B. Why dangerous:** Attackers can try thousands of passwords (**brute force**) or lists of leaked passwords (**credential stuffing**).
- **C. Where:** `POST /api/auth/login`.
- **D. Normal user:** logs in, maybe mistypes once or twice.
- **E. Flaw allows:** 20 failed guesses followed by a success, no obstruction; changing the header resets the counter.
- **F. Reproduce:**
```bash
for i in $(seq 1 15); do
  curl -s -o /dev/null -X POST $API/api/auth/login -H 'Content-Type: application/json' -H 'X-Forwarded-For: 10.99.0.7' \
    -d "{\"email\":\"alice.anderson@tenant.alpha.com\",\"password\":\"wrong$i\"}"
done
curl -s -X POST $API/api/auth/login -H 'Content-Type: application/json' -H 'X-Forwarded-For: 10.99.0.7' \
  -d '{"email":"alice.anderson@tenant.alpha.com","password":"demo_password_123"}'   # still works
```
- **G. Evidence:** 15 `AUTH_FAILURE` events then `AUTH_SUCCESS` from the same IP in `GET /api/security/events`.
- **H. Secure:** lock/slow per **account and** per real network address, exponential delay, CAPTCHA/MFA, never trust client-supplied IP headers.
- **I. SentinelForge/SOC:** RULE-001 (>10 failures from one IP in 5 min -> *Brute Force*) and RULE-002 (success after many failures -> *Possible Account Takeover*).

---

## VULN-010 - JWT authorization weakness

- **A. What:** *Authentication* (valid login token) is not *authorization* (allowed to do this). Here the endpoint trusts the **role
  written inside the token** and never double-checks the database.
- **B. Why dangerous:** A user who was **demoted** (or an account whose rights changed) keeps the old role until the token expires (15 min).
- **C. Where:** `GET /api/vulnerable/admin`. Secure twin: `GET /api/vulnerable/admin/secure`.
- **D. Normal user:** a STAFF token gets `403 {"authenticated":true,"authorized":false}`.
- **E. Flaw allows:** a token minted while the user was an admin keeps working after they stop being one.
- **F. Reproduce:**
```bash
curl -s $API/api/vulnerable/admin -H "Authorization: Bearer $ALICE"   # 403 : authenticated, but not authorized
curl -s $API/api/vulnerable/admin -H "Authorization: Bearer $ADMIN"   # 200 : role claim says SUPER_ADMIN
# stale-token idea: demote the admin account in the DB, the OLD token still works here, but the /secure route refuses it.
```
- **G. Evidence:** response includes both `jwtRole` and `currentDbRole`; they can differ -> proof the DB was never checked. A `ADMIN_ACTION` event (critical when they differ).
- **H. Secure:** `/api/vulnerable/admin/secure` re-reads the user from the database and checks the **current** role and `active` flag.
- **Not included:** dangerous "algorithm confusion" tricks are intentionally absent.
- **I. SentinelForge:** compare token claims to server-side truth; test role changes mid-session (CWE-285).

---

## VULN-011 - Mass assignment

- **A. What:** The server takes the whole request body and writes **every field** to the record. A user editing their profile should be
  limited to `name`, `email`, `phone`, but the vulnerable code also accepts `role`, `tenantId`, `isAdmin`.
- **B. Why dangerous:** Self-promotion to admin, or moving yourself into another tenant.
- **C. Where:** `PATCH /api/users/:id` (and `/vulnerable/:id`). Secure twin: `PATCH /api/users/secure/:id`.
- **D. Normal user:** changes their name/email/phone.
- **E. Flaw allows:** `{"role":"TENANT_ADMIN"}` changes the role.
- **F. Reproduce (as a STAFF user; first find one):**
```bash
STAFF_EMAIL=$(curl -s $API/api/admin/users -H "Authorization: Bearer $ADMIN" | node -pe \
  "JSON.parse(require('fs').readFileSync(0)).find(u=>u.role==='STAFF'&&u.tenantId==='tenant-alpha').email")
STAFF=$(login $STAFF_EMAIL demo_password_123)
STAFF_ID=$(curl -s $API/api/auth/me -H "Authorization: Bearer $STAFF" | node -pe "JSON.parse(require('fs').readFileSync(0)).userId")

curl -s -X PATCH $API/api/users/$STAFF_ID -H "Authorization: Bearer $STAFF" -H 'Content-Type: application/json' \
  -d '{"role":"TENANT_ADMIN"}'      # the role changes; log in again and admin routes now work
```
  (Put the role back afterwards with the admin token, or re-run `./scripts/seed.sh`.)
- **G. Evidence:** response shows the new role; `PRIVILEGE_CHANGE` (critical, `oldRole STAFF -> newRole TENANT_ADMIN`, `actorRole STAFF`) and an audit log entry `ROLE_CHANGED`.
- **H. Secure:** `PATCH /api/users/secure/:id` copies only an **allowlist** (`name`, `email`, `phone`) and logs ignored fields as suspicious.
- **I. SentinelForge/SOC:** send extra fields and see them persist; RULE-005 (STAFF/USER ends up with an admin role).

---

## VULN-012 - Business logic: fake payment workflow

- **A. What:** Not every bug is technical. *Business logic* flaws abuse the **rules of the business**. Ours: the payment endpoint trusts
  the client for the payment status, the amount, and the resulting order status.
- **B. Why dangerous:** Free products, over-refunds, reused coupons - real money loss, with perfectly "valid" requests.
- **C. Where:** `POST /api/orders`, `POST /api/payments`, `POST /api/refunds`. Secure twin: `POST /api/payments/secure`.
- **D. Normal flow:** create order (status `pending`) -> pay the **server-calculated** total -> status becomes `paid`.
- **E. Flaw allows:** paying `0.01` for an order, or marking it paid with no real payment.
- **F. Reproduce:**
```bash
ORDER=$(curl -s -X POST $API/api/orders -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  -d '{"items":[{"productId":"prod-1","quantity":1}]}')
ORDER_ID=$(echo "$ORDER" | node -pe "JSON.parse(require('fs').readFileSync(0)).id")
echo "$ORDER"        # status pending, total ~49.99

curl -s -X POST $API/api/payments -H "Authorization: Bearer $ALICE" -H 'Content-Type: application/json' \
  -d "{\"orderId\":\"$ORDER_ID\",\"status\":\"completed\",\"orderStatus\":\"paid\",\"amount\":0.01}"
```
- **G. Evidence:** payment `amount: 0.01` while the order total is ~49.99 and the order is now `paid`; `PAYMENT_UPDATED` event (high, `note: business_logic_abuse`, MITRE T1565).
- **H. Secure:** `/api/payments/secure` accepts only `orderId`+`method`, requires state `pending`, and **computes the amount on the server**.
- **No real money:** no payment gateway exists anywhere in the lab.
- **I. SentinelForge:** an AI/business-rule tester replays the flow with tampered fields; RULE-009 flags tampered payments.

---

## VULN-013 - Insecure file upload

- **A. What:** Upload features accept files from users. If the server does not restrict **type, name, size and storage**, attackers upload
  dangerous content (scripts, HTML, huge files).
- **B. Why dangerous:** In real systems an uploaded script can be executed (web shell) or served back to other users.
- **C. Where:** `POST /api/files/upload` (vulnerable). Secure twin: `POST /api/files/upload/secure`.
- **D. Normal user:** uploads a small `.txt/.json/.csv/.png/.jpg`.
- **E. Flaw allows:** uploading web-type files such as `.html`, `.svg`, `.php` with no validation.
- **F. Reproduce:**
```bash
echo '<h1>hello</h1>' > /tmp/page.html
curl -s -X POST $API/api/files/upload        -H "Authorization: Bearer $ALICE" -F "file=@/tmp/page.html"   # accepted, validated:false
curl -s -X POST $API/api/files/upload/secure -H "Authorization: Bearer $ALICE" -F "file=@/tmp/page.html"   # 400 File type not allowed
```
- **G. Evidence:** `"validated": false, "riskyExtension": true`; `FILE_UPLOAD` event (high, MITRE T1505.003).
- **H. Secure:** allowlist of types, sanitized file names, size limit (2 MB), storage outside any executable/served path.
- **Lab safety guard:** `.exe .sh .bat .ps1 ...` are **always refused**, even by the vulnerable route, and nothing uploaded is ever executed.
- **I. SentinelForge:** upload benign-but-forbidden types and see them accepted (CWE-434, OWASP A04:2021).

---

## VULN-014 - Secret exposure (fake secrets)

- **A. What:** *Secrets* are credentials: API keys, tokens, passwords. Committing them to code or config files is dangerous because anyone
  with repo access (or a leaked copy) gets them.
- **B. Why dangerous:** Attackers scan public repos for keys within minutes of a leak.
- **C. Where:** `config/demo.env` contains **obviously fake** values: `DEMO_API_KEY=demo_secret_123`, `DEMO_DB_PASSWORD=demo_password`, etc.
- **D. Normal practice:** secrets live in a secret manager or untracked env vars. (`config/secure.env` shows the right pattern.)
- **E. Flaw:** the fake secrets are sitting in the repository.
- **F. Reproduce:** run any secret scanner (for example Gitleaks) on the folder, or just open `config/demo.env`.
- **G. Evidence:** scanner output listing the file and key names.
- **H. Secure:** rotate/remove, load from the environment at runtime, add scanners to CI.
- **I. SentinelForge:** repository scanning (CWE-540, OWASP A05:2021). **These are fake and protect nothing.**

---

## DEPENDENCY-DEMO-001 - Outdated dependency (optional)

- **A. What:** Apps use third-party libraries. Some versions have publicly known vulnerabilities (listed as **CVEs**,
  numbered public vulnerability reports).
- **C. Where:** `server/package.json` uses `multer ^1.4.5-lts.1` (npm itself warns "Multer 1.x is impacted by a number of vulnerabilities").
- **F. Reproduce:** `cd server && npm audit` or `osv-scanner`.
- **H. Secure:** upgrade to the maintained major version and re-test uploads.
- **I. SentinelForge:** software-composition analysis (SCA): match dependency versions to known-vulnerability databases. Details: `docs/DEPENDENCIES.md`.

---

## Quick comparison table

| ID | Name | Vulnerable endpoint | Secure twin | Sev |
|---|---|---|---|---|
| 001 | IDOR/BOLA | `GET /api/users/:id` | `/api/users/secure/:id` | high |
| 002 | Cross-tenant | `GET /api/orders/:id` | `/api/orders/secure/:id` | critical |
| 003 | Broken RBAC | `/api/admin/users/vulnerable` ... | `/api/admin/users` ... | high |
| 004 | NoSQL injection | `POST /api/auth/vulnerable-login` | `/api/auth/secure-login` | critical |
| 005 | Stored XSS | `POST /api/comments` | `/api/comments/safe` | high |
| 006 | SSRF | `POST /api/fetch-url` | `/api/fetch-url/secure` | high |
| 007 | Path traversal | `GET /api/files/download` | `/api/files/download/secure` | high |
| 008 | Command injection (simulated) | `POST /api/tools/ping` | `/api/tools/ping/secure` | medium |
| 009 | Weak rate limit | `POST /api/auth/login` | (design fix) | medium |
| 010 | JWT authz | `GET /api/vulnerable/admin` | `/api/vulnerable/admin/secure` | high |
| 011 | Mass assignment | `PATCH /api/users/:id` | `/api/users/secure/:id` | high |
| 012 | Business logic | `POST /api/payments` | `/api/payments/secure` | high |
| 013 | Insecure upload | `POST /api/files/upload` | `/api/files/upload/secure` | medium |
| 014 | Secret exposure | `config/demo.env` | `config/secure.env` | medium |

Next: **Part 3** explains security events, the SOC, simulators, incidents, the attack graph, and the full demo flow.
