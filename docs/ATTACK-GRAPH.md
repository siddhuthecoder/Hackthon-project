# Attack Graph

## Build logic (`modules/graph/service.ts: buildAttackPath()`)

Runs automatically the moment an incident is created (same step as correlation). Built strictly from data already in the database for that incident — nothing invented:

```
IP (incident.sourceIp, if known)
  --AUTHENTICATED-->
USER (incident.users[0] or subject)
  --ACCESSED-->
ENDPOINT (incident.assets[0])
  --EXPLOITED-->                     (only if a correlation exists)
VULNERABILITY (vulnKey: title, cwe, severity)
  --ACCESSES-->
ASSET ("Data behind <endpoint>")
```

If no correlation exists yet, the graph stops at ENDPOINT — still a real, correct graph, just shorter. The `summary` field is plain text describing what actually happened: either *"user-101 exploited VULN-001 via /api/users/:userId"* or, with no correlation, *"user-101 triggered RULE-003 against /api/users/:userId (no prior finding correlated yet)"*.

## Node/edge types

Matches the master spec's taxonomy where applicable: `USER`, `IP`, `ENDPOINT`, `VULNERABILITY`, `ASSET`. (`APPLICATION`, `DATABASE`, `TENANT`, `DEVICE` node types from the original spec weren't needed for the hero flow and aren't currently emitted — the builder is a plain function and easy to extend if a future incident type needs them.)

Edge types used: `AUTHENTICATED`, `ACCESSED`, `EXPLOITED`, `ACCESSES`.

## Frontend rendering

`sentinelforge/frontend/src/components/AttackGraphView.tsx`, using `@xyflow/react` (React Flow). Nodes are color-coded by type (vulnerability = red, endpoint = amber, user = blue, asset = purple). A simple grid layout positions nodes (no auto-layout library) — readable for the hero flow's graph size (4–6 nodes), not tuned for large graphs.

One real bug was found and fixed here during the live browser walkthrough: React Flow needs its parent container to report a non-zero width at mount time; the container only had an explicit height, so the graph rendered empty. Fixed by adding `width: '100%'` to the container's inline style. See `docs/IMPLEMENTATION-STATUS.md`.

## API

`GET /api/incidents/:id/attack-graph` → `{ summary, nodes[], edges[] }`, ready to hand straight to React Flow (`id, type, label, metadata` per node; `id, source, target, type, label` per edge).
