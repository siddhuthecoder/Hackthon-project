You are a senior cybersecurity engineer, AI engineer, backend architect, frontend engineer, DevSecOps engineer, and hackathon technical lead.

We are building a hackathon project called:

# SENTINELFORGE AI
### Autonomous AI Security Engineer

Tagline:
"Find the weakness. Detect the attack. Understand the attack path. Fix it. Prove it's fixed."

==================================================
1. PROJECT VISION
==================================================

Build a working end-to-end cybersecurity platform that combines:

1. AI Application Security
2. Vulnerability Scanning
3. Controlled AI Pentesting
4. SOC / Security Monitoring
5. AI Incident Investigation
6. Vulnerability + Attack Correlation
7. Attack Path / Attack Graph
8. Threat Intelligence
9. AI Remediation
10. Fix Verification
11. Human-approved Security Response

The most important differentiator is:

SentinelForge must connect vulnerabilities discovered BEFORE an attack with security events observed DURING an attack.

Example:

Scanner discovers:

BOLA/IDOR on:
GET /api/students/:id

Later:

SOC observes:

User A
→ accesses student 101
→ accesses student 102
→ accesses student 103
→ accesses student 104

SentinelForge should correlate:

Known BOLA vulnerability
+
Suspicious API activity
+
Same user
+
Same endpoint
+
Cross-user/cross-tenant access

and create:

"Possible exploitation of previously discovered BOLA vulnerability."

Then:

AI investigates
→ builds attack path
→ recommends containment
→ generates remediation
→ verifies the fix.

The complete loop must work.

==================================================
2. IMPORTANT SAFETY REQUIREMENTS
==================================================

This is a cybersecurity hackathon project.

Everything must be designed for authorized security testing.

Build a LOCAL / DOCKER-ONLY vulnerable demo application.

Never target:

- real websites
- real companies
- external systems
- cloud metadata endpoints
- real credentials
- real payment systems
- real personal data
- arbitrary host commands
- real data exfiltration

All offensive security functionality must operate against:

1. Our own vulnerable demo application
2. localhost
3. Docker services
4. fake users
5. fake credentials
6. fake data

Attack simulations must be controlled and deterministic.

==================================================
3. TECHNOLOGY STACK
==================================================

Use:

Frontend:
- Next.js
- TypeScript
- Tailwind CSS
- React
- React Flow
- Recharts

Backend:
- Node.js
- TypeScript
- Fastify or Express
- REST APIs

Database:
- PostgreSQL for SentinelForge platform data
- Redis for queues/events

Vector/RAG:
- pgvector or another simple vector database

AI:
- LangGraph
- LLM provider abstraction
- embeddings
- RAG

Security tools:

- Semgrep
- OWASP ZAP
- Nuclei
- Trivy
- Gitleaks
- OSV
- dependency scanning

Infrastructure:

- Docker
- Docker Compose

Use existing security tools instead of reinventing scanners.

The differentiator is the AI orchestration, correlation, attack graph, investigation, remediation and verification.

==================================================
4. REPOSITORY STRUCTURE
==================================================

Create a monorepo:

sentinelforge/
    
    apps/
        web/
        api/
        worker/
    
    packages/
        shared/
        security-engine/
        ai-engine/
        correlation-engine/
        attack-graph/
        detection-engine/
        remediation-engine/
        verification-engine/
    
    vulnerable-lab/
        frontend/
        api/
        worker/
        scripts/
        nginx/
    
    infrastructure/
        docker/
    
    docs/
    
    scripts/
    
    docker-compose.yml
    
    README.md

Keep components modular.

==================================================
5. TWO PRODUCTS MUST EXIST
==================================================

IMPORTANT:

There are TWO separate systems.

A. SENTINELFORGE

The actual cybersecurity platform.

B. SENTINELFORGE VULNERABLE DEMO LAB

A deliberately vulnerable SaaS application that SentinelForge scans, monitors and tests.

Do NOT mix them together.

Architecture:

                    SENTINELFORGE

                         |
          +--------------+--------------+
          |              |              |
       APPSEC           SOC            AI
          |              |              |
          +--------------+--------------+
                         |
                    CORRELATION
                         |
                    ATTACK GRAPH
                         |
                    AI RESPONSE
                         |
                    REMEDIATION
                         |
                    VERIFICATION


                         ↓

              VULNERABLE DEMO LAB

==================================================
6. VULNERABLE DEMO LAB
==================================================

Build a realistic small multi-tenant SaaS.

Use:

Next.js
Node.js
MongoDB
Redis
Nginx
Docker

Tenants:

- Alpha School
- Beta School
- Gamma School

Users:

- SUPER_ADMIN
- TENANT_ADMIN
- MANAGER
- STAFF
- USER

Entities:

- tenants
- users
- students
- teachers
- courses
- products
- orders
- files
- audit logs
- security events

Authentication:

- JWT
- refresh tokens
- sessions

Create intentionally vulnerable endpoints.

==================================================
7. VULNERABILITIES
==================================================

Implement safe demo versions of:

1. BOLA / IDOR

Example:

GET /api/students/:id

Vulnerable behavior:

User A can access User B's record.

Secure behavior:

403 Forbidden.

--------------------------------------------------

2. Cross-Tenant Authorization

Tenant A user attempts:

GET /api/tenants/B/students

Should be blocked after remediation.

--------------------------------------------------

3. Broken RBAC

STAFF attempts:

POST /api/admin/users/:id/promote

Should be blocked.

--------------------------------------------------

4. Mass Assignment

Example vulnerable request allows:

{
    "name": "John",
    "role": "SUPER_ADMIN"
}

Secure implementation must whitelist allowed fields.

--------------------------------------------------

5. Weak Rate Limiting

Create controlled login brute-force simulation.

Never use real accounts.

--------------------------------------------------

6. Stored XSS

Use harmless proof-of-concept payloads.

No credential theft.

--------------------------------------------------

7. NoSQL Injection

Create a safe local demonstration.

--------------------------------------------------

8. Path Traversal

Use only fake local demo files.

--------------------------------------------------

9. SSRF

ONLY allow requests to a local Docker internal demo service.

Never access:

169.254.169.254

or any real external system.

--------------------------------------------------

10. Insecure File Upload

Only fake harmless files.

--------------------------------------------------

11. JWT Authorization Weakness

Demonstrate incorrect role/permission validation.

Do NOT implement dangerous algorithm-confusion attacks.

--------------------------------------------------

12. Business Logic Abuse

Create a fake payment/order workflow.

No real payment gateway.

==================================================
8. SECURITY EVENTS
==================================================

Every important action in the demo lab should generate structured events.

Event types:

AUTH_SUCCESS
AUTH_FAILURE
SESSION_CREATED
SESSION_REVOKED
API_REQUEST
API_ERROR
AUTHORIZATION_FAILURE
PRIVILEGE_CHANGE
ADMIN_ACTION
DATA_ACCESS
BULK_DATA_ACCESS
CROSS_TENANT_ACCESS_ATTEMPT
FILE_UPLOAD
FILE_DOWNLOAD
SUSPICIOUS_REQUEST
RATE_LIMIT_TRIGGERED
PAYMENT_CREATED
PAYMENT_UPDATED
SECURITY_FINDING_TRIGGERED

Event schema:

{
    id,
    timestamp,
    eventType,
    severity,
    userId,
    tenantId,
    sourceIp,
    endpoint,
    method,
    statusCode,
    requestId,
    metadata
}

==================================================
9. ATTACK SIMULATORS
==================================================

Create controlled attack simulations.

Directory:

/vulnerable-lab/scripts/simulate/

Implement:

simulate-bruteforce
simulate-account-takeover
simulate-idor
simulate-cross-tenant
simulate-privilege-escalation
simulate-api-abuse
simulate-data-access
simulate-suspicious-admin

Each simulation must:

1. Use fake accounts
2. Target localhost only
3. Generate realistic security events
4. Be deterministic
5. Be easy to trigger from UI
6. Never attack external systems

Example:

POST /api/security-lab/simulate/idor

should generate:

User:
user_101

Requests:

/api/students/101
/api/students/102
/api/students/103
/api/students/104

==================================================
10. SENTINELFORGE ASSET DISCOVERY
==================================================

Implement an asset inventory.

Assets:

- applications
- APIs
- endpoints
- repositories
- containers
- databases
- services

User can:

ADD APPLICATION

Fields:

Name
Environment
Base URL
Repository
Authentication type

For the hackathon demo, primarily support:

LOCAL DEMO APPLICATION

After adding an application:

Discover:

- endpoints
- technologies
- authentication
- API routes
- security headers
- dependencies
- source repository
- exposed services

Display an asset inventory.

==================================================
11. APPLICATION SECURITY ENGINE
==================================================

Implement:

SAST
SCA
Secret scanning
API scanning
DAST

Integrate:

Semgrep
Trivy
Gitleaks
OSV
OWASP ZAP
Nuclei

Create a common finding format:

{
    id,
    title,
    type,
    severity,
    confidence,
    cwe,
    owasp,
    assetId,
    endpoint,
    evidence,
    description,
    impact,
    remediation,
    status
}

Statuses:

OPEN
CONFIRMED
FALSE_POSITIVE
FIXED
VERIFIED

==================================================
12. AI VULNERABILITY ANALYSIS
==================================================

When a finding is created:

AI should analyze:

- vulnerability
- endpoint
- evidence
- affected asset
- authentication context
- tenant context
- possible impact
- related findings

AI output:

1. What is wrong?
2. Why does it matter?
3. How was it detected?
4. Evidence
5. Possible attack path
6. Recommended remediation
7. Verification strategy

Do NOT let AI invent evidence.

Every claim must reference actual collected evidence.

==================================================
13. API SECURITY ENGINE
==================================================

Discover API endpoints.

Build an API inventory:

METHOD
PATH
AUTH
ROLE
TENANT
PARAMETERS
REQUEST BODY
RESPONSE
STATUS

Test:

- authentication
- authorization
- BOLA
- RBAC
- tenant isolation
- input validation
- rate limiting
- excessive data exposure
- mass assignment
- business logic

Prioritize authorization and tenant isolation for the demo.

==================================================
14. AI PENTEST ENGINE
==================================================

Create an AI-controlled security testing workflow.

Flow:

RECON
 ↓
DISCOVER ENDPOINTS
 ↓
UNDERSTAND AUTH
 ↓
MAP ROLES
 ↓
MAP RESOURCES
 ↓
TEST AUTHORIZATION
 ↓
TEST INPUTS
 ↓
VALIDATE FINDINGS
 ↓
BUILD ATTACK PATH

Use LangGraph.

Agents:

ReconAgent
AuthorizationAgent
VulnerabilityAgent
ValidationAgent
AttackPathAgent

Every agent must return structured output.

Do not allow unrestricted autonomous execution.

Use allowlisted tools and targets.

==================================================
15. SOC ENGINE
==================================================

Build a security monitoring pipeline.

Flow:

Demo Application
      ↓
Security Events
      ↓
Redis
      ↓
Event Normalizer
      ↓
Detection Engine
      ↓
Correlation Engine
      ↓
Incident Engine
      ↓
AI Investigation

Implement deterministic detection rules first.

Examples:

Rule 1:

More than 10 failed logins from one IP within 5 minutes.

→ BRUTE_FORCE

Rule 2:

Many failed logins followed by success.

→ POSSIBLE_ACCOUNT_TAKEOVER

Rule 3:

One user accesses many resource IDs quickly.

→ POSSIBLE_IDOR

Rule 4:

User accesses another tenant.

→ CROSS_TENANT_ATTACK

Rule 5:

STAFF changes ADMIN role.

→ PRIVILEGE_ESCALATION

Rule 6:

Large number of records accessed quickly.

→ POSSIBLE_DATA_EXFILTRATION

==================================================
16. INCIDENT ENGINE
==================================================

Incident schema:

{
    id,
    title,
    severity,
    status,
    detectedAt,
    sourceIp,
    users,
    assets,
    events,
    findings,
    attackPath,
    confidence,
    recommendedActions
}

Statuses:

OPEN
INVESTIGATING
CONTAINED
RESOLVED
FALSE_POSITIVE

Automatically create incidents from high-confidence detections.

==================================================
17. AI INVESTIGATION ENGINE
==================================================

This is one of the most important parts.

When an incident is created:

AI receives:

- security events
- users
- IP addresses
- endpoints
- vulnerabilities
- assets
- audit logs
- historical events
- threat intelligence
- attack graph

AI must answer:

1. What happened?
2. Who was involved?
3. What asset was targeted?
4. What evidence supports the conclusion?
5. What vulnerability may have been exploited?
6. Is there a relationship between the vulnerability and observed attack?
7. What is the attack path?
8. What is the likely impact?
9. What should security team do next?

AI must distinguish:

FACT
INFERENCE
UNCERTAINTY

Never present speculation as fact.

==================================================
18. THE CORE CORRELATION ENGINE
==================================================

This is the MAIN DIFFERENTIATOR.

Build:

Vulnerability ↔ Endpoint
Vulnerability ↔ Asset
User ↔ Event
User ↔ Vulnerability
Event ↔ Endpoint
Event ↔ Incident
Finding ↔ Incident
Finding ↔ Attack Path

Example:

Finding:

VULN-001
BOLA
/api/students/:id

Events:

User 101
accessed student 102
103
104
105

Correlation engine should detect:

Same endpoint
+
Known BOLA
+
Same user
+
Unauthorized object access
+
High frequency

Then produce:

CORRELATION:

"Observed activity is consistent with exploitation of VULN-001."

Include confidence score based on explicit evidence.

==================================================
19. ATTACK GRAPH
==================================================

Implement graph visualization using React Flow.

Node types:

USER
IP
DEVICE
APPLICATION
API
ENDPOINT
VULNERABILITY
ASSET
DATABASE
TENANT

Edges:

ACCESSED
AUTHENTICATED
EXPLOITED
TARGETED
BELONGS_TO
ESCALATED_TO
ACCESSES

Example graph:

Compromised User
      ↓
School API
      ↓
BOLA Vulnerability
      ↓
Cross-Tenant Boundary
      ↓
Student Records
      ↓
Bulk Data Access

The graph must be generated from actual collected evidence.

==================================================
20. THREAT INTELLIGENCE
==================================================

Add a threat intelligence module.

Support concepts for:

CVE
CWE
OWASP
OSV
EPSS
CISA KEV

For the hackathon, don't build a giant threat intelligence platform.

Use threat intelligence to enrich findings.

Example:

CVE
→ affected dependency
→ severity
→ exploitability
→ known exploited status

==================================================
21. AI SECURITY BRAIN
==================================================

Create a central AI orchestration layer.

Use LangGraph.

Agents:

1. Recon Agent
2. Vulnerability Agent
3. SOC Investigation Agent
4. Correlation Agent
5. Attack Path Agent
6. Threat Intelligence Agent
7. Remediation Agent
8. Verification Agent

Orchestrator:

SecurityBrain

Flow:

INPUT
 ↓
CLASSIFY
 ↓
GATHER EVIDENCE
 ↓
RUN TOOLS
 ↓
ANALYZE
 ↓
CORRELATE
 ↓
DECIDE
 ↓
RECOMMEND
 ↓
HUMAN APPROVAL IF REQUIRED
 ↓
ACTION
 ↓
VERIFY

Never make the LLM the source of truth.

Tools and database evidence are the source of truth.

==================================================
22. AI REMEDIATION
==================================================

When a vulnerability is selected:

Show:

Root cause
Affected code
Why vulnerability exists
Secure implementation
Suggested patch
Tests to run
Security regression test

Example:

Vulnerable:

findStudent(id)

Secure:

findStudent(id, currentUser)

and verify:

student.ownerId === currentUser.id

or:

student.tenantId === currentUser.tenantId

Generate a patch suggestion.

Do not automatically modify production code.

Use human approval.

==================================================
23. FIX VERIFICATION
==================================================

This is another critical demo feature.

After a fix:

User clicks:

VERIFY FIX

SentinelForge runs the same controlled security test.

Example:

Before:

GET /api/students/102

200 OK

After:

GET /api/students/102

403 FORBIDDEN

Display:

BEFORE
❌ Vulnerable

AFTER
✅ Blocked

Verification:

PASSED

Finding:

VERIFIED_FIXED

==================================================
24. SECURITY RESPONSE
==================================================

Implement safe response actions.

Examples:

- revoke session
- disable demo user
- mark incident contained
- create remediation task
- block simulated IP
- isolate demo asset
- generate security ticket

Dangerous actions must require human approval.

Never automatically perform destructive actions.

==================================================
25. FRONTEND
==================================================

Create a professional cybersecurity SaaS UI.

Pages:

/login

/dashboard

/assets

/applications

/applications/:id

/scans

/findings

/findings/:id

/incidents

/incidents/:id

/incidents/:id/investigation

/attack-graph

/soc

/events

/audit-logs

/threat-intelligence

/remediation

/verification

/security-lab

/settings

==================================================
26. DASHBOARD
==================================================

Dashboard should show:

Security Score

Critical Findings

High Findings

Open Incidents

Active Attack Paths

Assets

Recent Security Events

AI Security Summary

Example:

"1 critical vulnerability is currently being actively targeted in the demo environment."

Show evidence.

==================================================
27. FINDINGS PAGE
==================================================

Table:

Severity
Finding
Asset
Endpoint
CWE
OWASP
Status
Detected
AI Analysis

Click finding → detailed page.

==================================================
28. INCIDENT PAGE
==================================================

Show:

Incident title
Severity
Status
Confidence

Timeline

Evidence

Affected users

Source IP

Affected assets

Related vulnerabilities

Attack graph

AI investigation

Recommended actions

Remediation

Verification

==================================================
29. SOC PAGE
==================================================

Show:

Live security events

Detection rules

Alerts

Incidents

Event timeline

Filters:

severity
event type
user
tenant
IP
endpoint
time

==================================================
30. SECURITY LAB PAGE
==================================================

This page controls the vulnerable demo environment.

Buttons:

RUN IDOR ATTACK

RUN BRUTE FORCE

RUN CROSS-TENANT ATTACK

RUN PRIVILEGE ESCALATION

RUN API ABUSE

RUN DATA ACCESS SIMULATION

RUN ACCOUNT TAKEOVER

Each attack should display:

Started
Requests generated
Events generated
Detection triggered
Incident created

==================================================
31. AI ASSISTANT
==================================================

Create an AI security assistant.

Example questions:

"What happened?"

"Why was this incident created?"

"Is this related to a known vulnerability?"

"Show me the attack path."

"What is the impact?"

"How do I fix this?"

"Verify whether the vulnerability is fixed."

The assistant must use actual platform data through tools.

It must not hallucinate security events.

==================================================
32. DATABASE
==================================================

Create migrations and models for:

organizations
users
roles
permissions
assets
applications
endpoints
scan_runs
scan_results
vulnerabilities
security_events
detections
incidents
incident_events
attack_paths
attack_nodes
attack_edges
threat_indicators
remediation_tasks
verification_runs
audit_logs
agent_runs

Use proper indexes.

Important indexes:

security_events.timestamp
security_events.eventType
security_events.userId
security_events.tenantId
security_events.sourceIp

vulnerabilities.severity
vulnerabilities.status

incidents.status
incidents.severity

==================================================
33. API DESIGN
==================================================

Create clean REST APIs.

Examples:

POST /api/applications

GET /api/applications

POST /api/scans

GET /api/scans/:id

GET /api/findings

GET /api/findings/:id

POST /api/findings/:id/analyze

GET /api/events

GET /api/incidents

GET /api/incidents/:id

POST /api/incidents/:id/investigate

GET /api/incidents/:id/attack-path

POST /api/remediation/:id/generate

POST /api/verification/:id/run

POST /api/security-lab/simulate/idor

POST /api/security-lab/simulate/bruteforce

POST /api/security-lab/simulate/cross-tenant

==================================================
34. REAL-TIME EVENTS
==================================================

Use WebSockets or Server-Sent Events.

When attack simulation starts:

SOC page should update live.

Example:

09:31:02
AUTH_SUCCESS

09:31:04
API_REQUEST

09:31:04
CROSS_TENANT_ACCESS_ATTEMPT

09:31:05
SUSPICIOUS_REQUEST

09:31:06
DETECTION_TRIGGERED

09:31:07
INCIDENT_CREATED

==================================================
35. AUDIT LOGGING
==================================================

Track:

actor
action
target
oldValue
newValue
timestamp
tenantId
requestId

Important actions:

LOGIN
LOGOUT
SCAN_STARTED
FINDING_CREATED
INCIDENT_CREATED
AI_INVESTIGATION
REMEDIATION_GENERATED
RESPONSE_APPROVED
FIX_VERIFIED

==================================================
36. AI OUTPUT FORMAT
==================================================

AI responses should be structured.

Example:

{
    "summary": "...",
    "facts": [],
    "evidence": [],
    "inferences": [],
    "uncertainties": [],
    "relatedFindings": [],
    "attackPath": [],
    "impact": "...",
    "recommendedActions": [],
    "confidence": 0.94
}

Never allow the model to invent evidence.

==================================================
37. HACKATHON DEMO SCENARIO
==================================================

THIS MUST WORK END-TO-END.

Demo:

STEP 1

Start:

docker compose up

STEP 2

Open SentinelForge.

STEP 3

Add:

"SentinelForge School SaaS"

Target:

http://demo.local

STEP 4

Run security scan.

STEP 5

Scanner discovers:

HIGH
BOLA / IDOR

GET /api/students/:id

STEP 6

Open finding.

Show:

Why vulnerable
Evidence
Impact
AI analysis

STEP 7

Open SOC.

Everything currently looks normal.

STEP 8

Open Security Lab.

Click:

SIMULATE IDOR ATTACK

STEP 9

SOC receives events live.

STEP 10

Detection rule triggers.

STEP 11

Incident automatically created.

STEP 12

Click:

INVESTIGATE WITH AI

STEP 13

AI correlates:

Known BOLA vulnerability
+
Same endpoint
+
Same user
+
Unauthorized resource access
+
Repeated access

STEP 14

AI generates:

Possible exploitation of VULN-001.

STEP 15

Open attack graph.

Show:

User
 ↓
API
 ↓
BOLA
 ↓
Cross-Tenant Access
 ↓
Student Records

STEP 16

AI recommends:

1. Revoke session
2. Investigate accessed records
3. Fix authorization
4. Run verification

STEP 17

Open remediation.

Show secure authorization implementation.

STEP 18

Apply the code fix manually or through the controlled demo patch mechanism.

STEP 19

Click:

VERIFY FIX

STEP 20

SentinelForge reruns the same controlled attack.

Before:

200 OK

After:

403 FORBIDDEN

STEP 21

Show:

Vulnerability:
FIXED

Attack:
BLOCKED

Verification:
PASSED

Incident:
RESOLVED

==================================================
38. DEMO STORY
==================================================

The final presentation should communicate:

"Most security tools either find vulnerabilities OR monitor attacks.

SentinelForge connects both worlds.

First, it finds a vulnerability.

Then, when an attack occurs, the SOC detects suspicious activity.

The AI connects the live attack to the previously discovered vulnerability.

It builds the attack path.

It explains the impact.

It recommends remediation.

Then it verifies that the vulnerability is actually fixed.

So SentinelForge closes the security loop."

==================================================
39. TESTING
==================================================

Write tests for:

Backend:

- authentication
- authorization
- tenant isolation
- BOLA
- RBAC
- event generation
- detection rules
- incident creation
- correlation
- remediation
- verification

Frontend:

- dashboard
- findings
- incidents
- SOC
- attack graph
- security lab

Integration:

Run:

scan
→ vulnerability
→ attack
→ event
→ detection
→ incident
→ AI investigation
→ correlation
→ remediation
→ verification

This entire workflow must pass.

==================================================
40. OBSERVABILITY
==================================================

Every service must have structured logs.

Use:

requestId
traceId
service
timestamp
severity

Provide a simple health endpoint:

GET /health

and:

GET /ready

==================================================
41. SECURITY
==================================================

SentinelForge itself must follow secure practices.

Implement:

- input validation
- authentication
- authorization
- RBAC
- tenant isolation
- rate limiting
- secure headers
- parameterized queries
- secret management
- audit logging
- safe error handling
- no secrets in Git
- environment variables

Never commit API keys.

Create:

.env.example

==================================================
42. DOCUMENTATION
==================================================

Create:

README.md

docs/ARCHITECTURE.md
docs/API.md
docs/DATABASE.md
docs/AI-ARCHITECTURE.md
docs/SECURITY.md
docs/DEMO.md
docs/DEVELOPMENT.md

Also create:

docs/HACKATHON-PITCH.md

Include:

Problem
Solution
Architecture
AI
Innovation
Security
Demo
Impact
Future Scope

==================================================
43. DEVELOPMENT STRATEGY
==================================================

DO NOT try to build everything simultaneously.

Build in phases.

PHASE 1

Repository
Docker
Database
Authentication
Organizations
Users
Roles
Basic frontend

PHASE 2

Vulnerable Demo Lab

PHASE 3

Asset discovery

PHASE 4

Security scanning

PHASE 5

Findings management

PHASE 6

SOC event ingestion

PHASE 7

Detection engine

PHASE 8

Incident engine

PHASE 9

Correlation engine

PHASE 10

Attack graph

PHASE 11

LangGraph AI agents

PHASE 12

AI investigation

PHASE 13

AI remediation

PHASE 14

Fix verification

PHASE 15

Real-time UI

PHASE 16

End-to-end testing

PHASE 17

Demo polishing

==================================================
44. CRITICAL PRIORITY
==================================================

If time becomes limited:

DO NOT add more features.

Prioritize this exact workflow:

BOLA discovery
    ↓
BOLA finding
    ↓
IDOR attack simulation
    ↓
SOC detection
    ↓
Incident
    ↓
AI investigation
    ↓
Vulnerability correlation
    ↓
Attack graph
    ↓
AI remediation
    ↓
Fix
    ↓
Verification

This workflow must be extremely polished.

==================================================
45. DO NOT OVERBUILD
==================================================

Do NOT initially build:

- full enterprise SIEM
- full EDR
- Kubernetes security
- complete cloud security platform
- 1000 detection rules
- every CVE
- every programming language
- real firewall management
- real endpoint isolation
- real-world offensive attacks
- dozens of dashboards
- dozens of AI agents

Build a polished hackathon MVP.

==================================================
46. ENGINEERING RULES
==================================================

You must:

1. Keep code production-quality.
2. Use TypeScript.
3. Use strict typing.
4. Validate inputs.
5. Handle errors properly.
6. Add tests.
7. Avoid duplicated logic.
8. Keep modules independent.
9. Use environment variables.
10. Never hardcode secrets.
11. Add useful comments for security-critical code.
12. Keep APIs documented.
13. Use database migrations.
14. Use proper indexes.
15. Make Docker setup reproducible.
16. Make the entire project runnable locally.

==================================================
47. IMPORTANT AI ENGINEERING RULE
==================================================

Do NOT make the project:

"ChatGPT + dashboard."

AI must actually perform security reasoning.

AI must:

- consume evidence
- call security tools
- correlate data
- reason about attack paths
- explain findings
- investigate incidents
- recommend remediation
- verify security results

Use deterministic systems wherever deterministic systems are better.

Example:

Detection:

RULE ENGINE

Investigation:

AI

Correlation:

RULES + GRAPH + AI

Final action:

HUMAN APPROVAL

==================================================
48. FINAL ACCEPTANCE CRITERIA
==================================================

The project is considered complete only when I can run:

docker compose up

and demonstrate:

1. Login
2. Dashboard
3. Add demo application
4. Discover application
5. Run scan
6. Find BOLA
7. View AI analysis
8. Start IDOR attack
9. See live SOC events
10. Detection triggers
11. Incident appears
12. AI investigates
13. AI correlates vulnerability + attack
14. Attack graph appears
15. AI recommends remediation
16. Fix is applied
17. Verification runs
18. Attack is blocked
19. Finding becomes VERIFIED_FIXED
20. Incident becomes RESOLVED

No fake screenshots.

No fake buttons.

No hardcoded "success" states.

The demo must be backed by real application behavior.

==================================================
49. START NOW
==================================================

First inspect the repository.

If the repository is empty:

Create the complete monorepo structure.

Then implement PHASE 1.

After completing each phase:

1. Run tests.
2. Fix errors.
3. Run lint.
4. Run type checking.
5. Update documentation.
6. Verify Docker.
7. Only then move to the next phase.

Maintain:

docs/IMPLEMENTATION-STATUS.md

with:

Phase
Feature
Status
Tests
Known Issues
Next Step

Use:

TODO
IN_PROGRESS
DONE
BLOCKED

Do not claim a feature is complete until it actually works.

At the end of every major phase, explain:

- What was implemented
- Files created/changed
- APIs created
- Database changes
- Tests added
- How to run it
- What remains

Start implementing now.