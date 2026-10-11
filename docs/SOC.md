# SOC (Security Operations Center)

## Event pipeline

```
CyberLab logs a real event (securityLogger.ts)
  -> GET /api/security/events (CyberLab's own API)
  -> modules/events/ingest.ts polls this every CYBERLAB_POLL_MS (default 1.5s)
  -> dedupe on (source="cyberlab", sourceId=CyberLab's own event id)
  -> stored in security_events
  -> published on the in-process bus (topic "event")
  -> streamed to any connected SOC page via SSE (/api/stream)
```

Events are also ingested immediately (not waiting for the next poll tick) right after a Security Lab attack simulation, so the demo feels instant (`modules/lab/routes.ts`).

## Event types supported

Whatever CyberLab emits is stored as-is (`eventType` is a free string, not an enum, on the SentinelForge side) — in practice: `AUTH_SUCCESS`, `AUTH_FAILURE`, `SESSION_CREATED`, `DATA_ACCESS`, `BULK_DATA_ACCESS`, `CROSS_TENANT_ACCESS_ATTEMPT`, `AUTHORIZATION_FAILURE`, `PRIVILEGE_CHANGE`, `SUSPICIOUS_REQUEST`, `FILE_UPLOAD`, `FILE_DOWNLOAD`, `API_REQUEST`, `API_ERROR`, and others CyberLab's own logger defines.

## Scanner traffic vs. attacker traffic

A real bug was found and fixed here during testing: the scanner's own vulnerability checks are real HTTP requests against CyberLab, and without special handling they tripped the same detection rules a live attacker would — creating incidents before anyone clicked "run attack."

Fix: every request `CyberLabAdapter` makes carries a fixed `X-Forwarded-For: 10.50.0.1` header (`SCANNER_SOURCE_IP` in `modules/cyberlab/adapter.ts`). `modules/detection/service.ts` excludes that IP from detection — the same way a real SOC allowlists its own authorized scanner's IP so it doesn't alert on itself. Real attacker traffic (via CyberLab's own `/api/security/simulate/*`) gets its own randomized IP per CyberLab's simulator, so it is never excluded.

## Live feed (SOC page)

`GET /api/stream?token=<jwt>` is a Server-Sent Events endpoint. The frontend's `/soc` page subscribes and renders every message with a timestamp, topic, and a one-line summary. Topics: `event`, `detection`, `incident`, `scan`, `verification`, `finding`.

Note: because this route writes the raw HTTP response directly (required for a streaming body), it bypasses Fastify's normal reply pipeline — including `@fastify/cors`'s automatic header injection. The route sets `Access-Control-Allow-Origin` by hand for this reason (found and fixed during the live browser walkthrough — see `docs/IMPLEMENTATION-STATUS.md`).

## Detection rules (5 of 6 from the master spec)

`modules/detection/rules.ts`: RULE-001 brute force, RULE-002 account takeover (many failures then a success from the same IP), RULE-003 IDOR enumeration, RULE-004 cross-tenant access, RULE-005 privilege escalation, RULE-006 data exfiltration. One spec rule category — "possible data exfiltration" — is folded into RULE-006 rather than kept separate from a generic "bulk access" rule; the other 5 map one-to-one to the spec's named rules.

## Threat intelligence

CWE/OWASP/representative-CVE context comes from a local reference dataset; EPSS scores and CISA KEV status are fetched live from the real public feeds (first.org, cisa.gov — no API key needed) with that local dataset as the fallback if a feed times out. See `docs/AI-ARCHITECTURE.md`'s ThreatIntelAgent and `modules/threatintel/`. Every scan syncs this against the application's findings by CWE.
