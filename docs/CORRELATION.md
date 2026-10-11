# Correlation Engine

This is the project's core differentiator: linking a vulnerability the scanner found earlier to an attack the SOC observes live.

## How it works (`modules/correlation/service.ts`)

Every detection rule names which vulnerability key(s) it is evidence for:

| Rule | Vulnerability |
|---|---|
| RULE-001 (brute force) | VULN-009 |
| RULE-002 (account takeover) | VULN-009 |
| RULE-003 (IDOR enumeration) | VULN-001 |
| RULE-004 (cross-tenant access) | VULN-002 |
| RULE-005 (privilege escalation) | VULN-011 |

When an incident is created from one of these rules, `correlateIncident()` runs immediately (no extra click needed):

1. Look up the finding(s) for that vulnerability key, scoped to the application.
2. Build an evidence object: the shared endpoint, the incident's subject/rule, the finding's status, how many events back the incident.
3. Write a plain-language reason:
   > *"Live activity matched detection rule RULE-003 against /api/users/:userId, the same endpoint where VULN-001 (Broken Object Level Authorization) was previously confirmed by the scanner. This is consistent with exploitation of VULN-001."*
4. Confidence is blended from the incident's and the finding's own confidence scores (never invented).
5. Store as a `Correlation` document — never created without this evidence attached.

## What "never create a correlation without evidence" means here

A correlation only exists when:
- a real detection rule actually fired (from real ingested events), **and**
- a real finding with a matching vuln key actually exists (from a real scanner run)

If either side is missing — no finding on record for that endpoint, or the incident came from a rule with no vuln mapping (e.g. data exfiltration, which has no fixed `findings` entry) — no correlation is created, and the attack graph falls back to a shorter, still-real graph (user → endpoint only, no vulnerability node).

## Where it surfaces

- `GET /api/incidents/:id` → `correlations[]` + `findings[]`
- `GET /api/findings/:id` → `relatedIncidents[]` (the reverse link)
- The AI investigation prompt receives the correlated finding(s) as part of its real input data, which is why its summary can say *"consistent with exploitation of VULN-001"* — that phrase is derived from the correlation, not hardcoded in the AI code.
- The attack graph (`docs/ATTACK-GRAPH.md`) adds a VULNERABILITY node only when a correlation exists.

## Verified behavior

See `docs/IMPLEMENTATION-STATUS.md`: live test confirmed the "Possible IDOR Attack" incident correctly correlated to VULN-001 with the exact reason text above, and the reverse link appeared on the VULN-001 finding page.
