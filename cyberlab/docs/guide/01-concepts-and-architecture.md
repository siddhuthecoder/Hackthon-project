# SentinelForge Vulnerable Cybersecurity Demo Lab - Beginner Guide

## Part 1 of 3: What the lab is, how it is built, who the users are, how login works

> Written for: a developer who can program but has never studied cybersecurity.
> Every security word is defined the first time it appears. Every demonstration runs only against
> `localhost` / the Docker lab. Nothing here targets a real system.

Guide map:
- **Part 1 (this file):** concepts, purpose, architecture, users/roles, data, authentication
- **Part 2:** all 15 vulnerabilities, one by one, with reproduction commands
- **Part 3:** security events, audit logs, SOC, simulators, incidents, attack graph, findings, pages, demo flow, glossary, one-page summary

---

## 1. First, the vocabulary (plain language)

| Term | Plain meaning | Everyday analogy |
|---|---|---|
| **Cybersecurity** | Protecting software, data and users from being misused, stolen or broken by people who should not have access. | Locks, alarms and guards for a building, but for software. |
| **Vulnerability** | A mistake or weakness in a system that could let someone do something they should not be allowed to do. | A door that looks locked but opens if you push it the right way. |
| **Attacker** | A person (or program) trying to misuse a system. In our lab the "attacker" is our own script or us, acting on purpose. | Someone testing every door in a building. |
| **Attack** | The actual steps taken to use a vulnerability. | Walking in through that door. |
| **Exploit** | The specific trick, request or input that triggers a vulnerability. | The exact push-and-twist that opens the broken door. |
| **Penetration testing (pentest)** | Authorized, controlled attacking of a system by a security tester, to find weaknesses before real attackers do. | Hiring a locksmith to try breaking into your own house, with your permission. |
| **AppSec (Application Security)** | The part of security that focuses on the app's own code and logic: login, permissions, input handling, APIs. | Checking the building's doors and locks, not the neighborhood. |
| **SOC (Security Operations Center)** | The people, process and tools that watch security activity all day and react when something looks wrong. | The control room with security cameras. |
| **Security log / security event** | A recorded fact about something security-relevant: "login failed", "admin changed a role", "someone read another tenant's order". | Camera footage and door-badge records. |
| **Incident** | A group of suspicious events that the SOC decides is a real security problem worth handling. | "Someone is trying every door on floor 2" - an alert ticket. |
| **Attack path** | The chain of steps an attacker takes from the first foothold to the final goal. | Parking lot -> side door -> hallway -> server room -> take the files. |
| **Vulnerability detection** | Finding weaknesses *before* anyone abuses them (scanning, testing, code review). | An inspector checking locks. |
| **Threat detection** | Noticing an attack *while it is happening* from logs and behavior. | The guard seeing someone jiggle door handles. |
| **Remediation** | Fixing the weakness (changing code, config or permissions). | Replacing the broken lock. |
| **Security verification** | Re-testing after the fix to prove the weakness is really gone and the attack now fails. | The inspector returns and pushes on the door again. |

---

## 2. What exactly is this lab?

The **SentinelForge Vulnerable Cybersecurity Demo Lab** is a small, realistic web application
(a fake business software product) that we built **on purpose to contain security mistakes**.
We own it. It runs only on your computer in Docker. All data in it is fake.

It is **not** the SentinelForge security product. It is the **target** the product will practice on.

```
   Vulnerable Demo Application   <-- THIS LAB (what you have now)
              |
              v
        SentinelForge            <-- the future security product (not built yet)
              |
              v
   Scan / Detect / Simulate attacks
              |
              v
   Investigate / Respond / Fix
              |
              v
          Verify
```

Think of a **flight simulator**. A pilot-training company does not train on a real plane with real
passengers. It builds a simulator that behaves like a plane, can have faults injected, and is safe to
crash. This lab is the simulator. SentinelForge is the training and monitoring system that learns to
handle the faults.

What the lab gives us:
1. A believable app (users, companies, orders, payments, files).
2. 14 deliberately planted weaknesses (plus 1 optional outdated dependency).
3. A recorder that writes a security event for everything meaningful.
4. Attack simulators that really exercise those weaknesses against the local app.
5. A small SOC engine that detects the attacks and opens incidents.
6. A web UI to see all of it.
7. "Secure twin" endpoints, so we can show before-fix vs after-fix.

---

## 3. Why we need the lab (why not just build SentinelForge?)

A security product is only impressive if it can **prove** it works. To prove it you need:

| Needed to demonstrate | Needs from the target app |
|---|---|
| Finding vulnerabilities | Real vulnerabilities to find |
| Reproducing them | Behavior that can be triggered on demand |
| Simulating attacks | An app that really responds to attack traffic |
| Generating security events | Logging inside the app |
| SOC detecting suspicious activity | Realistic, labeled event streams |
| AI investigating an incident | Incident data with evidence |
| Correlating vulnerability with attack | Both a known weakness and an attack that used it |
| Generating remediation | Code that can actually be fixed |
| Applying the fix | A secure version of the behavior |
| Verifying the fix | Ability to replay the attack and watch it fail |

You cannot attack a real company's app for a demo (illegal and unsafe). You also cannot honestly
demo "we found a vulnerability" if there is no vulnerability. So we **build a safe, owned target**.

### A simple real-world example (IDOR)

A school runs a web app where students look at their own grades.

```
Before the problem (correct):
  Student A  --asks for-->  /api/users/101   -->  Student A's data    OK

The vulnerability (IDOR / BOLA): the app never checks "is this record yours?"
  Student A  --changes 101 to 102-->  /api/users/102  -->  Student B's data   NOT OK
```

- **IDOR** = *Insecure Direct Object Reference*. **BOLA** = *Broken Object Level Authorization*
  (the newer name for the same idea in API security). The app trusts the ID in the URL and forgets to
  check ownership.

How SentinelForge helps:
1. A scanner notices `/api/users/:id` returns other people's data -> a **finding** (VULN-001).
2. Later, the SOC sees one user reading 12 different user IDs in seconds -> an **incident**.
3. The AI connects the two: "this incident is that exact vulnerability being abused."
4. It proposes the fix (check ownership), applies it, replays the attack, and shows it is **blocked**.

In our lab the real IDs look like `user-101`, `user-102` (not just numbers), but the idea is identical.

---

## 4. The architecture (what is running)

```
                         NGINX  (port 80)  <-- the front door
                           |
              +------------+------------+
              |                         |
              v                         v
        Next.js Web UI              REST API (Node/Express)
        (frontend)                  (api, port 3001)
                                          |
                    +---------------------+----------------------+
                    |                     |                      |
                    v                     v                      v
                 MongoDB                Redis            Background Worker
              (data storage)       (event messaging)       (worker)

   plus: internal-service  (a tiny private service used only for the SSRF demo)
```

Seven Docker containers (the original plan listed six; the 7th is the private SSRF target):

| Service | What is it? | Why the lab needs it | What you see / how it matters |
|---|---|---|---|
| **frontend** | The website (Next.js + React + Tailwind). | Gives humans a dashboard. | Pages like Dashboard, Incidents, Attack Simulation. |
| **api** | The backend server. An **API** (Application Programming Interface) is a set of URLs that programs call to read/write data, e.g. `GET /api/orders`. | Almost every web attack happens through API requests. Our vulnerabilities live here. | Login, orders, payments, admin, security endpoints. |
| **mongodb** | The database (MongoDB). Stores all fake data as JSON-like documents. | Databases hold the valuable data attackers want. Also where security events and incidents are stored. | Collections: users, orders, security_events, incidents... |
| **redis** | A very fast in-memory store/message bus. | Every security event is also **published** on a Redis channel (`security-events`) so a SOC can consume events in real time without querying the database. | Used like a live news feed of security events. |
| **worker** | A background program with no web UI. | Security work should not slow down web requests: it runs detection rules every 30 seconds, creates notifications for new incidents, cleans expired sessions, and listens to the Redis event stream. | Why incidents appear "by themselves" a few seconds after an attack. |
| **nginx** | A **reverse proxy**: a front-door server that receives all browser traffic and forwards it to the right backend. | Looks like production (one entry point, `http://localhost`). Also a classic place real companies put protections. | Browser -> nginx -> frontend or api. |
| **internal-service** | A tiny private HTTP service with one secret endpoint. | It is the safe, local-only target for the SSRF demo. | `GET /internal/demo-secret` returns a fake secret. Not reachable from your browser, only from inside Docker. |

**Docker** packages each program with everything it needs into a **container**, a lightweight
isolated mini-computer. Why it is perfect for a security lab:
- **Reproducible:** `docker compose up -d` gives anyone the same environment.
- **Isolated:** the vulnerable app runs inside a sealed network and cannot touch your real files or systems.
- **Disposable:** break it, reset it (`./scripts/reset.sh`), start clean.

Exposed to your computer: only port **80** (nginx, the main entry) and **3001** (the API directly,
handy for scripts). Mongo, Redis and the internal service are not exposed at all.

---

## 5. The application itself: a small multi-tenant SaaS

- **SaaS** (Software as a Service) = software you use over the internet as a subscription, like
  Slack or Shopify. Many customers use the *same running application*.
- **Tenant** = one customer organization inside that shared app.
- **Multi-tenant** = many tenants share one app and one database, and the app is supposed to keep
  each tenant's data completely separate.

Our three tenants:

| Tenant | Think of it as |
|---|---|
| `tenant-alpha` | School A |
| `tenant-beta` | School B |
| `tenant-gamma` | School C |

Rule: **School A must never see School B's data.** This separation is called **tenant isolation**.

Why tenant isolation is a security issue: in SaaS the whole business promise is "your data is yours."
One bug that crosses the wall can leak *every* customer's data at once. It is among the most serious
bugs a SaaS company can have. That is VULN-002 in this lab.

What the app contains for each tenant: users, customers, products, orders, payments, files, comments.

---

## 6. Users, roles, authentication vs authorization

| | Question it answers | Example |
|---|---|---|
| **Authentication** (AuthN) | *Who are you?* | Logging in with email + password proves you are Alice. |
| **Authorization** (AuthZ) | *What are you allowed to do?* | Alice may view her own profile but may not delete other users. |

Most real breaches are not "someone cracked the login," they are "someone logged in normally and the
app forgot to check what they were allowed to do." That is why authorization bugs fill this lab.

**RBAC (Role-Based Access Control)**: permissions are attached to roles, and users get roles.

| Role | Meant for | Should be able to | Should NOT be able to |
|---|---|---|---|
| `USER` | A normal end user | See their own profile, orders of their tenant, post comments | Read other people's records, use admin features |
| `STAFF` | Employee doing day-to-day work | Same as user plus staff work | Admin pages, changing roles |
| `MANAGER` | Team lead | Read the tenant's users list | Promote users to admin, delete users |
| `TENANT_ADMIN` | Administrator of **one** tenant | Manage users **inside their own tenant** | Touch other tenants |
| `SUPER_ADMIN` | Platform owner | Manage everything across tenants | (almost nothing is off-limits) |

What goes wrong if authorization is coded badly:
- A `STAFF` user opens an admin page -> **privilege escalation** (gaining more power than intended).
- A `USER` reads another user's record -> **IDOR/BOLA**.
- A tenant reads another tenant's order -> **cross-tenant leak**.

Seeded accounts (all fake; password for everyone except the admin is `demo_password_123`):

| Who | Email | Role |
|---|---|---|
| System admin | `admin@sentinelforge.lab` / `admin_demo_123` | SUPER_ADMIN |
| Alice (the usual "victim/attacker" in demos) | `alice.anderson@tenant.alpha.com` | USER, id `user-101`, tenant-alpha |
| Others | `first.last@tenant.<alpha\|beta\|gamma>.com` | mix |

Seeded counts: 30 users (5 admins, 10 managers, 10 staff, 5 users), 100 customers, 100 products,
200 orders, 50 payments, 100 audit logs, 150 past security events, 3 past incidents, 14 findings.

---

## 7. The data (entities) and why each matters for security

| Entity | What it represents | Why it exists | Example | Why security cares |
|---|---|---|---|---|
| **User** | A person who can log in | Needed for login, roles, ownership | `user-101`, Alice, role USER, tenant-alpha | Account takeover and role abuse target users. Passwords are stored only as hashes. |
| **Tenant** | A customer organization | Multi-tenant model | `tenant-beta`, plan "pro" | Isolation between tenants is the core promise. |
| **Product** | Something the tenant sells | Realistic business data | `prod-1` "Quantum Router v1", price 49.99 | Normal data; also target for comments (XSS). |
| **Order** | A customer purchase | Realistic business data with money | `order-2`, tenant-beta, status `paid`, a fake total | Contains customer + money data; cross-tenant read is a leak. |
| **Customer** | A buyer belonging to a tenant | Business contact data | `cust-5`, Acme Corp, email (fake) | Personal data (PII) is what attackers steal. |
| **Payment** | A (fake) payment record | Shows business-logic abuse | `pay-2`, completed, bank | Money logic can be cheated (VULN-012). |
| **File** | Metadata of an uploaded file | Supports file features | `file-ab12cd`, `report.txt` | Uploads are a classic attack entrance. |
| **Comment** | Text users post about a product | Supports the XSS demo | "Great router!" | User-typed text that other users' browsers display. |
| **Security event** | One recorded security-relevant fact | The raw material of the SOC | `AUTH_FAILURE` from IP 10.77.5.9 | Without events nothing can be detected. |
| **Audit log** | A permanent "who changed what" record | Accountability / investigations | "admin changed user-112 STAFF -> MANAGER" | Proves what happened after the fact. |
| **Security finding** | A known weakness (VULN-001...014) | What a scanner reports | VULN-001, HIGH, `/api/users/:id` | The "list of problems" in the lab. |
| **Incident** | A detected attack, grouping events | What the SOC raises | "Possible IDOR Attack", critical | The "alarm ticket." |

---

## 8. Authentication in detail

**Login.** You send email + password to `POST /api/auth/login`. The server looks you up and compares
the password against a stored **hash** (a one-way scrambled form of the password; the server never
stores the real password).

```
POST /api/auth/login
{ "email": "alice.anderson@tenant.alpha.com", "password": "demo_password_123" }

200 OK
{ "accessToken": "eyJhbGciOi...", "refreshToken": "eyJhbGciOi...",
  "user": { "id": "user-101", "role": "USER", "tenantId": "tenant-alpha" } }
```

**JWT (JSON Web Token).** A signed text token the server hands you after login. It contains small
facts ("claims") such as `userId`, `email`, `role`, `tenantId` and an expiry time. The server signs it
with a secret key, so nobody can change the contents without the signature breaking. On every later
request you send `Authorization: Bearer <token>` and the server knows who you are without asking for
your password again.

| Concept | Meaning in this lab |
|---|---|
| **Access token** | Short-lived (15 minutes) "ticket" used on every API call. |
| **Refresh token** | Longer-lived (7 days) token used only to get a new access token (`POST /api/auth/refresh`). |
| **Session** | A database record (`sessions`) of a login: who, from which IP, which refresh token, revoked or not. |
| **Logout / session revocation** | `POST /api/auth/logout` marks the session revoked so its refresh token stops working. A `SESSION_REVOKED` event is logged. |
| **Password reset** | `forgot-password` records a reset request (demo only, no email is sent); `reset-password` sets a new password. Both log `PASSWORD_RESET`. |

Endpoints: `register`, `login`, `logout`, `refresh`, `forgot-password`, `reset-password`, `me`.

What can go wrong with authentication (and which lab piece shows it):

| Problem | Meaning | In the lab |
|---|---|---|
| **Brute force** | Trying many passwords until one works. | Simulator 01, VULN-009 |
| **Account takeover (ATO)** | An attacker ends up controlling someone else's account. | Simulator 02 |
| **Weak session handling** | Tokens that live too long or are never revoked. | Session records + logout |
| **Token problems** | Trusting what is inside a token without checking the server's own data. | VULN-010 |
| **Missing authentication** | An endpoint that forgets to require login at all. | (Lesson: we found and fixed `/me`, which originally forgot it) |
| **Injection into login** | Input that changes how the login query works. | VULN-004 |

Next: **Part 2** walks through every vulnerability with commands you can run.
