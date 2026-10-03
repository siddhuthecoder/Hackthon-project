# SENTINELFORGE AI — AUTONOMOUS END-TO-END HACKATHON IMPLEMENTATION SPECIFICATION

You are the lead engineer responsible for building the complete SentinelForge AI cybersecurity hackathon project.

You are not only a code generator.

You are responsible for:

- understanding the existing repository
- understanding the existing CyberLab
- designing the integration
- implementing the platform
- implementing the AI system
- implementing the security engines
- connecting all components
- testing every component
- testing integrations
- detecting failures
- fixing failures
- rerunning tests
- validating the complete end-to-end workflow
- documenting the implementation
- preparing the project for a live hackathon demonstration

The final result must be a REAL, WORKING, END-TO-END APPLICATION.

Do not create fake dashboards.
Do not create fake scan results.
Do not create fake incidents.
Do not create fake AI findings.
Do not create fake verification results.
Do not create buttons that only display hardcoded success messages.

Every important demo result must come from actual application behavior.

============================================================
0. PRIMARY OBJECTIVE
============================================================

Build:

# SENTINELFORGE AI

An Autonomous AI Security Engineer.

Core promise:

FIND THE WEAKNESS
        ↓
UNDERSTAND THE ATTACK PATH
        ↓
DETECT THE ATTACK
        ↓
INVESTIGATE
        ↓
RESPOND
        ↓
FIX
        ↓
VERIFY

The core differentiator is:

SentinelForge connects vulnerabilities discovered during Application Security testing with attacks observed by the SOC.

Example:

Before an attack:

SentinelForge discovers:

BOLA / IDOR

GET /api/students/:id

Later:

An attacker simulation performs:

User A
  ↓
/api/students/101
  ↓
/api/students/102
  ↓
/api/students/103
  ↓
/api/students/104

The SOC observes the behavior.

The detection engine identifies suspicious access.

The incident engine creates an incident.

The AI investigation engine analyzes the evidence.

The correlation engine connects:

KNOWN VULNERABILITY
+
LIVE SECURITY EVENTS
+
USER
+
ENDPOINT
+
RESOURCE ACCESS
+
TENANT CONTEXT

The AI explains:

"This activity is consistent with exploitation of a previously discovered BOLA vulnerability."

Then SentinelForge:

- builds the attack path
- explains impact
- recommends containment
- generates remediation guidance
- verifies the fix
- reruns the same controlled attack
- proves that the attack is blocked

This end-to-end loop is the MOST IMPORTANT part of the project.

============================================================
1. IMPORTANT EXECUTION RULE
============================================================

You have the complete project specification in this document.

You must implement the project PHASE BY PHASE.

However:

DO NOT WAIT FOR THE USER TO MANUALLY TELL YOU TO START THE NEXT PHASE.

After completing a phase:

1. Test it.
2. Fix failures.
3. Verify it.
4. Update implementation status.
5. Continue to the next phase automatically.

Only stop if:

- there is a genuine blocker that cannot be solved without user input
- a required external credential/API is unavailable and no safe local fallback exists
- the repository is corrupted or inaccessible
- an architectural decision genuinely requires user approval

Do NOT stop simply because a phase is finished.

Do NOT ask:

"Should I continue?"

Continue automatically.

============================================================
2. FIRST ACTION — INSPECT EVERYTHING
============================================================

Before changing code:

Inspect the complete repository.

The existing repository contains an authorized vulnerable cybersecurity laboratory.

The existing lab is:

cyberlab/

Treat it as an existing application.

DO NOT unnecessarily rebuild or replace the CyberLab.

First understand it.

Inspect:

- directory structure
- package.json
- Docker configuration
- docker-compose
- frontend
- backend/API
- routes
- controllers
- services
- database models
- authentication
- authorization
- roles
- tenants
- vulnerabilities
- security events
- audit logs
- attack simulations
- internal service
- demo files
- configuration
- environment variables
- documentation

Determine:

1. What already exists?
2. What works?
3. What is incomplete?
4. What vulnerabilities already exist?
5. What endpoints exist?
6. What security events exist?
7. What APIs can SentinelForge consume?
8. What changes are needed for integration?
9. What should NOT be changed?

Create:

docs/CYBERLAB-INTEGRATION-MAP.md

Document:

CyberLab component
→ endpoint
→ event
→ vulnerability
→ SentinelForge integration

Do not invent CyberLab behavior when the real repository provides it.

============================================================
3. REPOSITORY ARCHITECTURE
============================================================

Use the existing repository as the starting point.

Target structure:

Hackthon-project/

    cyberlab/
        existing vulnerable application

    sentinelforge/
        actual security platform

    docs/

    scripts/

    docker-compose.yml

    README.md

If the current repository structure differs:

DO NOT destroy working code.

Adapt the architecture intelligently.

============================================================
4. TWO DISTINCT SYSTEMS
============================================================

There are TWO systems.

SYSTEM A:

CYBERLAB

Purpose:

Deliberately vulnerable authorized target application.

SYSTEM B:

SENTINELFORGE

Purpose:

Security platform that discovers, scans, monitors, investigates, correlates, remediates and verifies the CyberLab.

Relationship:

CYBERLAB
   ↓
APIs
   ↓
Security Events
   ↓
SentinelForge
   ↓
AppSec
   ↓
SOC
   ↓
Correlation
   ↓
AI Investigation
   ↓
Attack Graph
   ↓
Remediation
   ↓
Verification

Do not merge the two products conceptually.

============================================================
5. TECHNOLOGY STACK
============================================================

Use the existing CyberLab technology where practical.

SentinelForge target stack:

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

Database:

- PostgreSQL

Cache / event transport:

- Redis

AI:

- LangGraph
- LLM abstraction
- embeddings
- RAG

Security tooling:

- Semgrep
- OWASP ZAP
- Nuclei
- Trivy
- Gitleaks
- OSV

Infrastructure:

- Docker
- Docker Compose

Use existing security tools instead of rebuilding them.

The differentiation is:

ORCHESTRATION
+
CORRELATION
+
AI REASONING
+
ATTACK GRAPH
+
REMEDIATION
+
VERIFICATION

============================================================
6. SECURITY SAFETY REQUIREMENTS
============================================================

All offensive security testing must be authorized and local.

Only target:

- CyberLab
- localhost
- Docker services
- fake accounts
- fake data

Never target:

- real websites
- real organizations
- production systems
- external IPs
- cloud metadata
- real credentials
- real customer data
- real payment systems

Never implement unrestricted host command execution.

Never implement real destructive actions.

Attack simulation must be controlled and deterministic.

Use fake data.

============================================================
7. DEVELOPMENT PHASES
============================================================

Implement in this order:

PHASE 0
Repository inspection and architecture mapping

PHASE 1
SentinelForge foundation

PHASE 2
CyberLab integration

PHASE 3
Asset discovery

PHASE 4
Application security scanning

PHASE 5
Finding management

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
AI security brain

PHASE 12
AI investigation

PHASE 13
Threat intelligence

PHASE 14
AI remediation

PHASE 15
Fix verification

PHASE 16
Security response

PHASE 17
Real-time UI

PHASE 18
End-to-end integration

PHASE 19
Testing and hardening

PHASE 20
Hackathon UI polish

PHASE 21
Final demo validation

You must automatically proceed through these phases.

============================================================
8. PHASE 0 — REPOSITORY INSPECTION
============================================================

Do not immediately start writing large amounts of code.

Inspect first.

Create:

docs/CYBERLAB-INTEGRATION-MAP.md

docs/IMPLEMENTATION-STATUS.md

docs/ARCHITECTURE.md

Record:

- existing architecture
- existing functionality
- existing vulnerabilities
- existing APIs
- existing events
- existing attack simulations
- integration requirements

Then begin Phase 1.

============================================================
9. PHASE 1 — SENTINELFORGE FOUNDATION
============================================================

Build:

- SentinelForge backend
- SentinelForge frontend
- PostgreSQL
- Redis
- Docker
- authentication
- organizations
- users
- roles
- permissions
- audit logging
- API structure
- configuration
- health checks

Use TypeScript strict mode.

Create:

GET /health

GET /ready

Create:

.env.example

Never commit real credentials.

Implement proper:

- validation
- authentication
- authorization
- RBAC
- error handling
- logging

============================================================
10. DATABASE
============================================================

Create database models/tables for:

organizations
users
roles
permissions
organization_members
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

Important relationships:

Organization
 ↓
Application
 ↓
Asset
 ↓
Endpoint
 ↓
Vulnerability

User
 ↓
Security Event
 ↓
Detection
 ↓
Incident

Vulnerability
 ↓
Incident
 ↓
Attack Path
 ↓
Remediation
 ↓
Verification

Add appropriate indexes.

Security event indexes:

timestamp
eventType
userId
tenantId
sourceIp
endpoint

Vulnerability indexes:

severity
status
assetId

Incident indexes:

status
severity
detectedAt

============================================================
11. PHASE 2 — CYBERLAB INTEGRATION
============================================================

Integrate with the EXISTING CyberLab.

Do not assume APIs.

Inspect actual implementation.

Build an adapter layer:

packages/cyberlab-adapter/

Responsibilities:

- connect to CyberLab
- discover APIs
- retrieve security events
- retrieve application information
- trigger authorized simulations
- retrieve findings when available
- normalize CyberLab data

Create a common interface so SentinelForge can later support other applications.

Example:

TargetAdapter

Methods:

discover()
getAssets()
getEndpoints()
getEvents()
runSecurityTest()
getHealth()

CyberLab should be the first implementation.

============================================================
12. PHASE 3 — ASSET DISCOVERY
============================================================

Implement asset inventory.

Assets:

- applications
- APIs
- endpoints
- services
- repositories
- containers
- databases

User workflow:

ADD APPLICATION

Fields:

Name
Environment
Base URL
Repository
Authentication type

For hackathon:

Primarily support:

LOCAL CYBERLAB

After adding:

discover:

- technologies
- endpoints
- authentication
- routes
- headers
- services
- dependencies where available

Store discovered information.

Display:

Application
→ Services
→ APIs
→ Endpoints

============================================================
13. PHASE 4 — APPLICATION SECURITY
============================================================

Build security scanning orchestration.

Integrate where practical:

Semgrep
Trivy
Gitleaks
OSV
OWASP ZAP
Nuclei

Create a normalized finding schema:

id
title
type
severity
confidence
cwe
owasp
assetId
applicationId
endpoint
evidence
description
impact
remediation
status
detectedAt

Statuses:

OPEN
CONFIRMED
FALSE_POSITIVE
FIXED
VERIFIED

The scanner must produce real results.

Do not hardcode findings.

============================================================
14. API SECURITY
============================================================

Analyze:

- authentication
- authorization
- RBAC
- tenant isolation
- BOLA
- input validation
- rate limiting
- excessive data exposure
- mass assignment
- business logic

For the hackathon, prioritize:

BOLA / IDOR

because it is the main demo.

============================================================
15. BOLA / IDOR DETECTION
============================================================

The primary vulnerability scenario is:

GET /api/students/:id

Expected:

A user can access their own authorized resource.

Unauthorized:

User A accesses User B's resource.

SentinelForge must identify this as:

BOLA / IDOR

Include:

CWE-639

OWASP API security classification where appropriate.

Evidence must come from the actual target behavior.

============================================================
16. PHASE 5 — FINDINGS MANAGEMENT
============================================================

Create:

/findings

/finding/:id

Finding page must show:

- title
- severity
- confidence
- affected asset
- endpoint
- evidence
- CWE
- OWASP
- impact
- remediation
- status
- related incidents
- related attack paths

Provide:

AI ANALYZE

button.

============================================================
17. AI VULNERABILITY ANALYSIS
============================================================

AI should analyze actual evidence.

It must answer:

What is wrong?

Why does it matter?

How was it detected?

What evidence proves it?

What could an attacker achieve?

What assets are affected?

What should be fixed?

How should the fix be verified?

AI must never invent evidence.

Use structured output:

summary
facts
evidence
inferences
uncertainties
impact
recommendations
confidence

Clearly distinguish:

FACT
INFERENCE
UNCERTAINTY

============================================================
18. PHASE 6 — SOC EVENT INGESTION
============================================================

Build:

CyberLab
 ↓
Security Events
 ↓
Adapter
 ↓
Normalizer
 ↓
Redis
 ↓
SentinelForge Event Store

Normalize events into:

id
timestamp
eventType
severity
userId
tenantId
sourceIp
endpoint
method
statusCode
requestId
metadata

Support:

- REST polling where needed
- WebSocket/SSE where available
- direct event ingestion
- replay for demo/testing

============================================================
19. SECURITY EVENTS
============================================================

Support:

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
SECURITY_FINDING_TRIGGERED

Do not create duplicate events unnecessarily.

============================================================
20. PHASE 7 — DETECTION ENGINE
============================================================

Implement deterministic rules BEFORE AI.

Rules:

BRUTE_FORCE:

More than 10 failed logins from same IP within 5 minutes.

ACCOUNT_TAKEOVER:

Many failed logins followed by successful login.

POSSIBLE_IDOR:

One user rapidly accesses many different object IDs.

CROSS_TENANT_ATTACK:

User accesses another tenant's resource.

PRIVILEGE_ESCALATION:

Lower privilege user performs privileged action.

POSSIBLE_DATA_EXFILTRATION:

Large volume of records accessed within a short period.

Each detection should include:

rule
evidence
events
confidence
severity
timestamp

============================================================
21. PHASE 8 — INCIDENT ENGINE
============================================================

Incident:

id
title
severity
status
detectedAt
sourceIp
users
assets
events
findings
attackPath
confidence
recommendedActions

Statuses:

OPEN
INVESTIGATING
CONTAINED
RESOLVED
FALSE_POSITIVE

Automatically create incidents from high-confidence detections.

============================================================
22. INCIDENT TIMELINE
============================================================

Show:

Login

Failed login

Successful login

API request

Authorization failure

Suspicious access

Detection

Incident creation

AI investigation

Response

Remediation

Verification

Use actual timestamps.

============================================================
23. PHASE 9 — CORRELATION ENGINE
============================================================

THIS IS THE CORE DIFFERENTIATOR.

Build correlation between:

Vulnerability
↔
Endpoint
↔
Asset
↔
User
↔
Security Event
↔
Incident

Example:

Finding:

VULN-001
BOLA
/api/students/:id

Live events:

User 101
accessed:

101
102
103
104
105

Correlation:

same endpoint
+
same user
+
known BOLA
+
unauthorized resource pattern
+
rapid repeated access

Output:

"Observed activity is consistent with exploitation of VULN-001."

Store:

correlationId
findingId
incidentId
evidence
confidence
reason

Never create a correlation without evidence.

============================================================
24. PHASE 10 — ATTACK GRAPH
============================================================

Use React Flow.

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

AUTHENTICATED
ACCESSED
TARGETED
EXPLOITED
BELONGS_TO
ESCALATED_TO
ACCESSES

Primary demo:

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

Every important graph relationship must come from actual data.

============================================================
25. PHASE 11 — AI SECURITY BRAIN
============================================================

Use LangGraph.

Create:

SecurityBrain

Agents:

1. ReconAgent
2. VulnerabilityAgent
3. InvestigationAgent
4. CorrelationAgent
5. AttackPathAgent
6. ThreatIntelAgent
7. RemediationAgent
8. VerificationAgent

Use tools.

Do not build one giant prompt.

Each agent should have:

- input schema
- tool access
- structured output
- validation
- error handling

The orchestrator should decide which agent to invoke.

============================================================
26. AI MUST USE TOOLS
============================================================

The AI should have access to controlled tools such as:

get_asset()
get_application()
get_endpoint()
get_vulnerability()
get_security_events()
get_user()
get_incident()
get_related_findings()
get_attack_path()
query_audit_logs()
run_authorized_security_test()
generate_remediation()
run_verification()

AI must not invent database information.

============================================================
27. PHASE 12 — AI INVESTIGATION
============================================================

When an incident occurs:

AI receives:

- incident
- events
- user
- IP
- endpoints
- vulnerabilities
- assets
- audit logs
- attack graph
- threat intelligence

AI produces:

SUMMARY

FACTS

EVIDENCE

TIMELINE

RELATED VULNERABILITIES

ATTACK PATH

IMPACT

INFERENCES

UNCERTAINTIES

RECOMMENDED ACTIONS

CONFIDENCE

Example:

FACT:

User 101 accessed five student IDs within 8 seconds.

FACT:

The endpoint is associated with VULN-001.

FACT:

VULN-001 is a BOLA vulnerability.

INFERENCE:

The observed activity is consistent with exploitation of VULN-001.

UNCERTAINTY:

The system cannot independently establish whether credentials were compromised before the observed activity.

This level of evidence discipline is required.

============================================================
28. PHASE 13 — THREAT INTELLIGENCE
============================================================

Add threat intelligence enrichment.

Support concepts for:

CVE
CWE
OWASP
OSV
EPSS
CISA KEV

Use external sources only where practical and available.

If external access is unavailable:

use a local cached/demo dataset.

Never make the entire application dependent on external APIs for the core demo.

============================================================
29. PHASE 14 — AI REMEDIATION
============================================================

When a finding is selected:

AI should explain:

Root cause

Affected code

Why it is vulnerable

Secure implementation

Suggested patch

Tests required

Security regression test

Example:

Vulnerable:

findStudent(id)

Secure:

findStudent(id, currentUser)

Then enforce:

resource ownership

OR

tenant ownership

OR

role authorization

depending on actual application architecture.

Do not blindly modify production code.

For the hackathon lab:

allow a controlled demo fix mechanism.

============================================================
30. PHASE 15 — FIX VERIFICATION
============================================================

This is mandatory.

User clicks:

VERIFY FIX

SentinelForge must rerun the same controlled security test.

Before:

GET /api/students/102

200 OK

After:

GET /api/students/102

403 Forbidden

Display:

BEFORE FIX
❌ Vulnerable

AFTER FIX
✅ Blocked

Verification:

PASSED

Finding:

VERIFIED_FIXED

Incident:

RESOLVED

This must be based on actual requests.

============================================================
31. PHASE 16 — SECURITY RESPONSE
============================================================

Implement safe response actions:

- revoke demo session
- disable demo user
- mark incident contained
- create remediation task
- block simulated IP
- isolate demo asset
- generate ticket

High-impact actions require human approval.

No destructive automatic actions.

============================================================
32. PHASE 17 — REAL-TIME UI
============================================================

Use:

WebSockets

or

Server-Sent Events

When attack simulation starts:

SOC should update live.

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

============================================================
33. FRONTEND PAGES
============================================================

Create:

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

============================================================
34. DASHBOARD
============================================================

Show:

Security posture

Critical findings

High findings

Open incidents

Active attack paths

Assets

Recent events

AI security summary

Use real database information.

Example AI summary:

"One high-severity authorization vulnerability is associated with a currently active suspicious access pattern."

Only show this if actual evidence supports it.

============================================================
35. SECURITY LAB UI
============================================================

Create a Security Lab page.

Show:

CyberLab status

Available attack simulations

Recent simulations

Results

Buttons:

RUN IDOR ATTACK

RUN BRUTE FORCE

RUN CROSS-TENANT ATTACK

RUN PRIVILEGE ESCALATION

RUN API ABUSE

RUN DATA ACCESS SIMULATION

RUN ACCOUNT TAKEOVER

Each simulation must:

- target CyberLab only
- use fake data
- generate real events
- trigger real detection logic
- create real incidents where applicable

============================================================
36. AI ASSISTANT
============================================================

Create an AI security assistant.

Example questions:

"What happened?"

"Why was this incident created?"

"Which vulnerability is related?"

"Show the attack path."

"What evidence supports this conclusion?"

"How do I fix this?"

"Is the vulnerability fixed?"

The assistant must query actual platform data.

No hallucinated security information.

============================================================
37. TESTING STRATEGY
============================================================

Every phase must include tests.

Unit tests:

- authorization
- event normalization
- detection rules
- correlation
- graph generation
- AI output validation
- remediation
- verification

Integration tests:

CyberLab
→ adapter
→ event ingestion
→ detection
→ incident

AppSec
→ finding
→ correlation
→ incident

AI
→ evidence
→ investigation
→ recommendation

End-to-end:

scan
→ vulnerability
→ attack
→ events
→ detection
→ incident
→ investigation
→ correlation
→ attack graph
→ remediation
→ fix
→ verification

============================================================
38. QUALITY GATES
============================================================

DO NOT move to the next phase until the current phase passes:

1. TypeScript compilation
2. Lint
3. Unit tests
4. Integration tests where applicable
5. Docker build
6. Service startup
7. API health checks
8. Relevant manual/API smoke tests

If a test fails:

DO NOT simply report it.

Investigate.

Fix.

Rerun.

Repeat until passing.

If a failure is genuinely blocked:

document it in:

docs/IMPLEMENTATION-STATUS.md

============================================================
39. AUTOMATED VALIDATION
============================================================

Create scripts such as:

scripts/test-all
scripts/test-e2e
scripts/health-check
scripts/demo-reset
scripts/demo-run

The exact implementation can use the project's package manager.

The goal is:

ONE COMMAND

to validate the core demo.

For example:

npm run test:e2e

should validate:

BOLA finding
→ IDOR attack
→ detection
→ incident
→ correlation
→ attack graph
→ verification

============================================================
40. DEMO RESET
============================================================

Create a deterministic reset mechanism.

Example:

npm run demo:reset

It should reset:

- database
- demo users
- demo tenants
- demo vulnerabilities
- incidents
- events
- attack paths
- remediation state

This ensures the hackathon demo can be repeated.

============================================================
41. FINAL DEMO
============================================================

The final demo MUST work from a clean state.

DEMO:

1. Start Docker.

2. Login to SentinelForge.

3. Add:

SentinelForge School SaaS

4. Connect to CyberLab.

5. Discover application.

6. Run security scan.

7. SentinelForge discovers:

HIGH — BOLA / IDOR

8. Open finding.

Show:

endpoint
evidence
impact
CWE
OWASP
AI explanation

9. Open SOC.

Show normal activity.

10. Open Security Lab.

11. Click:

RUN IDOR ATTACK

12. Live events appear.

13. Detection triggers.

14. Incident is created.

15. Open incident.

16. Click:

INVESTIGATE WITH AI

17. AI analyzes:

user
IP
endpoint
events
finding
asset
tenant
audit logs

18. AI identifies relationship:

KNOWN BOLA
+
LIVE SUSPICIOUS ACCESS

19. Open attack graph.

Show:

USER
 ↓
API
 ↓
BOLA
 ↓
TENANT BOUNDARY
 ↓
STUDENT DATA

20. AI recommends:

- revoke session
- investigate affected records
- fix authorization
- verify fix

21. Open remediation.

22. Show secure authorization fix.

23. Apply controlled lab fix.

24. Click:

VERIFY FIX

25. SentinelForge reruns the same authorized attack.

Before:

200 OK

After:

403 Forbidden

26. Show:

Vulnerability:
VERIFIED FIXED

Attack:
BLOCKED

Incident:
RESOLVED

This is the primary hackathon story.

============================================================
42. DO NOT OVERBUILD
============================================================

Do NOT spend time building:

- full enterprise SIEM
- full EDR
- Kubernetes security
- complete cloud security
- thousands of detection rules
- every CVE
- every programming language
- real firewall management
- real endpoint isolation
- unrestricted offensive automation
- dozens of unnecessary dashboards

Focus on:

ONE PERFECT SECURITY STORY.

============================================================
43. HACKATHON UX
============================================================

The UI must be professional.

Design principles:

- cybersecurity SaaS appearance
- clear severity
- strong hierarchy
- minimal clutter
- useful charts
- readable timelines
- understandable attack graph
- obvious evidence
- clear AI reasoning
- obvious remediation
- obvious verification

A judge should understand the system without reading the source code.

============================================================
44. AI DESIGN PRINCIPLES
============================================================

AI must NOT be:

"Chatbot + dashboard."

AI must actually perform:

- security reasoning
- evidence analysis
- correlation
- investigation
- attack path reasoning
- remediation generation
- verification planning

Use deterministic systems where deterministic systems are better.

Detection:

RULE ENGINE

Correlation:

RULES + GRAPH + AI

Investigation:

AI

Final security action:

HUMAN APPROVAL

============================================================
45. OBSERVABILITY
============================================================

Every service must have structured logs.

Include:

timestamp
service
severity
requestId
traceId
message

Implement:

/health

/ready

Useful startup logs.

Do not log secrets.

============================================================
46. SECURITY OF SENTINELFORGE ITSELF
============================================================

SentinelForge must itself implement:

- authentication
- authorization
- RBAC
- input validation
- rate limiting
- secure headers
- safe errors
- secret management
- audit logs
- tenant isolation
- parameterized queries
- secure defaults

No secrets in Git.

============================================================
47. DOCUMENTATION
============================================================

Create/update:

README.md

docs/ARCHITECTURE.md

docs/CYBERLAB-INTEGRATION-MAP.md

docs/API.md

docs/DATABASE.md

docs/AI-ARCHITECTURE.md

docs/SOC.md

docs/CORRELATION.md

docs/ATTACK-GRAPH.md

docs/REMEDIATION.md

docs/VERIFICATION.md

docs/SECURITY.md

docs/DEMO.md

docs/DEVELOPMENT.md

docs/IMPLEMENTATION-STATUS.md

docs/HACKATHON-PITCH.md

Documentation must describe actual implementation.

Do not document features that don't exist.

============================================================
48. IMPLEMENTATION STATUS
============================================================

Maintain:

docs/IMPLEMENTATION-STATUS.md

Format:

PHASE
STATUS
IMPLEMENTED
TESTS
KNOWN ISSUES
NEXT STEP

Statuses:

NOT_STARTED
IN_PROGRESS
TESTING
FAILED
FIXING
DONE
BLOCKED

Update it continuously.

============================================================
49. NO FAKE COMPLETION
============================================================

Never mark something DONE if:

- code only exists but doesn't run
- API exists but isn't connected
- UI exists but uses hardcoded data
- AI exists but isn't connected
- scanner exists but isn't producing real results
- SOC exists but doesn't receive events
- correlation exists but doesn't use real evidence
- verification exists but doesn't rerun the test

DONE means:

implemented
connected
tested
working

============================================================
50. FAILURE RECOVERY
============================================================

When you encounter an error:

1. Capture error.
2. Identify root cause.
3. Inspect relevant code.
4. Fix root cause.
5. Run targeted test.
6. Run broader test.
7. Continue.

Do not repeatedly apply random changes.

============================================================
51. DEPENDENCY MANAGEMENT
============================================================

Before adding dependencies:

Check whether an existing dependency already solves the problem.

Avoid unnecessary packages.

After adding dependencies:

- install
- build
- test
- update lockfile

Do not leave broken dependency versions.

============================================================
52. DATABASE MIGRATIONS
============================================================

All schema changes must use migrations.

Do not manually modify production-style schema without migration tracking.

Seed deterministic demo data.

============================================================
53. LOCAL DEVELOPMENT
============================================================

The final project must be easy to run.

Document:

Prerequisites

Installation

Environment variables

Database setup

Docker setup

Development mode

Testing

Demo reset

Demo execution

Example:

docker compose up --build

Then:

npm run test:e2e

Then:

npm run demo:reset

============================================================
54. FINAL ACCEPTANCE CRITERIA
============================================================

The project is COMPLETE only when ALL of the following work:

[ ] Repository builds

[ ] Docker builds

[ ] Docker starts

[ ] SentinelForge frontend starts

[ ] SentinelForge API starts

[ ] PostgreSQL works

[ ] Redis works

[ ] CyberLab starts

[ ] SentinelForge connects to CyberLab

[ ] Authentication works

[ ] RBAC works

[ ] Asset discovery works

[ ] Application discovery works

[ ] Security scan works

[ ] BOLA is discovered

[ ] Finding is stored

[ ] Finding UI works

[ ] AI finding analysis works

[ ] CyberLab attack simulation works

[ ] Security events are generated

[ ] Events reach SentinelForge

[ ] Detection rule works

[ ] Incident is created

[ ] Incident timeline works

[ ] AI investigation works

[ ] Correlation works

[ ] Vulnerability ↔ attack relationship is displayed

[ ] Attack graph works

[ ] AI remediation works

[ ] Controlled fix can be applied

[ ] Verification reruns the attack

[ ] Vulnerable state produces unauthorized response

[ ] Fixed state produces 403/blocked response

[ ] Finding becomes VERIFIED_FIXED

[ ] Incident becomes RESOLVED

[ ] Audit logs work

[ ] Tests pass

[ ] End-to-end test passes

[ ] Demo can be reset

[ ] Documentation is updated

============================================================
55. FINAL SELF-TEST
============================================================

Before declaring the project complete, perform the complete demo yourself through automated tests/API calls wherever possible.

Run:

1. Clean environment
2. Build
3. Start services
4. Reset demo
5. Login
6. Discover CyberLab
7. Scan
8. Confirm BOLA
9. Run IDOR simulation
10. Confirm events
11. Confirm detection
12. Confirm incident
13. Run AI investigation
14. Confirm correlation
15. Confirm attack graph
16. Generate remediation
17. Apply controlled fix
18. Run verification
19. Confirm attack blocked
20. Confirm finding fixed
21. Confirm incident resolved

If anything fails:

FIX IT.

Then rerun the complete workflow.

Do not stop after fixing only the immediate test.

============================================================
56. HACKATHON READINESS
============================================================

After all technical acceptance criteria pass:

Polish:

- UI
- loading states
- empty states
- errors
- animations where useful
- attack graph
- incident timeline
- AI output presentation
- security severity indicators
- demo reset
- README
- demo instructions

Create:

docs/HACKATHON-DEMO.md

Include exact:

1. Startup commands
2. Login credentials for demo
3. Scan steps
4. Attack simulation steps
5. SOC demonstration
6. AI investigation
7. Attack graph
8. Remediation
9. Verification
10. Reset procedure

============================================================
57. FINAL OUTPUT
============================================================

When the project is truly complete, provide:

1. Summary of architecture
2. Features implemented
3. Files/modules created
4. APIs created
5. Database schema
6. AI architecture
7. Security architecture
8. CyberLab integration
9. Tests executed
10. Test results
11. End-to-end result
12. How to run
13. How to reproduce the hackathon demo
14. Known limitations
15. Future improvements

Do not claim 100% completion if anything in the acceptance criteria is failing.

============================================================
58. MOST IMPORTANT PRIORITY
============================================================

If time or complexity becomes a problem:

STOP ADDING FEATURES.

Prioritize this exact flow:

CyberLab
   ↓
BOLA Discovery
   ↓
Finding
   ↓
IDOR Simulation
   ↓
Security Events
   ↓
SOC Detection
   ↓
Incident
   ↓
AI Investigation
   ↓
Vulnerability Correlation
   ↓
Attack Graph
   ↓
AI Remediation
   ↓
Apply Fix
   ↓
Verify Same Attack
   ↓
403 / BLOCKED
   ↓
VERIFIED FIXED
   ↓
INCIDENT RESOLVED

This flow must be flawless.

============================================================
59. BEGIN
============================================================

START NOW.

First:

1. Inspect the entire repository.
2. Inspect CyberLab completely.
3. Do not modify anything unnecessarily.
4. Create the integration map.
5. Create the implementation status document.
6. Create the architecture document.
7. Identify what already exists.
8. Identify what must be built.
9. Begin Phase 1.
10. Test Phase 1.
11. Fix Phase 1.
12. Continue automatically through every phase.
13. Do not wait for user approval between phases.
14. Keep the master specification as the source of truth.
15. Never fake completion.
16. Finish with the complete end-to-end acceptance test.

Your job is not finished when the code has been generated.

Your job is finished only when the complete SentinelForge attack-to-fix-to-verification workflow actually works.