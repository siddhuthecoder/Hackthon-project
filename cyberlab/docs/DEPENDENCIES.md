# Dependency Findings — SentinelForge Lab

The lab is designed to be scanned by SentinelForge (or any SAST/SCA tool). Two
findings live outside the application code and are reachable with standard
supply-chain tooling:

| Finding ID | Location | Kind | Severity |
|---|---|---|---|
| `DEPENDENCY-DEMO-001` | `server/package.json` → `"multer": "^1.4.5-lts.1"` | Outdated / end-of-life dependency | high |
| `VULN-014` | `config/demo.env` | Committed demo secrets (fake) | medium |

Both are **intentional**. Nothing in this repository may be deployed anywhere
other than a local, throwaway Docker lab. See the safety notice in `README.md`.

---

## DEPENDENCY-DEMO-001 — Multer 1.x is end-of-life

### What the lab ships

`server/package.json`:

```json
"dependencies": {
  "multer": "^1.4.5-lts.1"
}
```

`^1.4.5-lts.1` resolves to `1.4.5-lts.2`, the **last release of the 1.x line**.
Multer's own maintainers deprecated the whole 1.x line:

```console
$ npm view multer version deprecated
2.4.0 'Multer 1.x is impacted by a number of vulnerabilities, which have been
patched in 2.x. You should upgrade to the latest 2.x version.'

$ cd server && npm ls multer
sentinelforge-api@1.0.0 D:\cyberlab\server
`-- multer@1.4.5-lts.2
```

The lab uses Multer in `server/src/routes/files.ts` for both upload handlers
(`POST /api/files/upload` — VULN-013, and `POST /api/files/upload/secure`), so
the vulnerable component is genuinely on a request path, not a dead dependency.

### Why it matters

Multer 1.x carries a long chain of unauthenticated Denial-of-Service advisories
(all CWE-400 / CWE-772 class resource-exhaustion issues, several reachable
straight from the multipart parser before any application code runs). For a demo
API that is publicly reachable, that is exactly the kind of "known-vulnerable
dependency" a scanner is expected to flag.

### Finding it with `osv-scanner` (recommended — this is the one that flags it)

OSV carries the full advisory set for the whole 1.x line:

```console
# one-shot query against the OSV API
$ curl -s -X POST https://api.osv.dev/v1/query \
    -H 'Content-Type: application/json' \
    -d '{"version":"1.4.5-lts.1","package":{"name":"multer","ecosystem":"npm"}}'
```

11 advisories are returned, including:

| Advisory | Summary | Fixed in |
|---|---|---|
| `GHSA-44fp-w29j-9vj5` | DoS via memory leaks from unclosed streams | 2.0.0 |
| `GHSA-4pg4-qvpc-4q3h` | DoS from maliciously crafted requests | 2.0.0 |
| `GHSA-g5hg-p3ph-g8qg` | DoS via unhandled exception | 2.0.1 |
| `GHSA-fjgf-rc76-4x9p` | DoS via unhandled exception from malformed request | 2.0.2 |
| `GHSA-v52c-386h-88mc` | DoS via resource exhaustion | 2.1.0 |
| `GHSA-xf7r-hgr6-v32p` | DoS via incomplete cleanup | 2.1.0 |
| `GHSA-5528-5vmv-3xc2` | DoS via uncontrolled recursion | 2.1.1 |
| `GHSA-72gw-mp4g-v24j` | DoS via deeply nested field names | 2.2.0 |
| `GHSA-535w-7cp7-47q4` | DoS via oversized array index in field names | 2.3.0 |
| `GHSA-qvfw-j98x-7q72` | File size limit bypass via async `fileFilter` race condition | 2.3.0 |
| `GHSA-wc9g-mqfw-jrwm` | DoS via crafted multipart field names | 2.3.0 |

With the scanner installed:

```console
$ osv-scanner scan source -r .          # whole repository
$ osv-scanner scan source -L server/package.json
# -> server/package.json: multer 1.4.5-lts.1 - 11 known vulnerabilities (fix available in 2.4.0)
```

### Finding it with `npm audit`

`npm audit` resolves `^1.4.5-lts.1` to `1.4.5-lts.2`, which npm's own advisory
database currently treats as clean, so a straight `npm audit` in `server/`
reports nothing for Multer (it only reports one unrelated `uuid` advisory):

```console
$ cd server && npm audit
found 0 vulnerabilities        # for multer; see the note below
```

`npm audit` **does** flag the dependency the moment the resolved version falls
into a range npm tracks. Pinning the lab's declared version exactly reproduces
it:

```console
$ mkdir -p /tmp/multer-demo && cd /tmp/multer-demo
$ npm init -y
$ npm pkg set dependencies.multer=1.4.4
$ npm install --package-lock-only
$ npm audit
# npm audit report
# dicer  *
# Severity: high
# Crash in HeaderParser in dicer - https://github.com/advisories/GHSA-wm7h-9275-46v2
# fix available via `npm audit fix --force`
# Will install multer@2.4.0, which is a breaking change
# node_modules/dicer
#   busboy  <=0.3.1
#     Depends on vulnerable versions of dicer
#   multer  <=2.2.0
#     Depends on vulnerable versions of busboy
# 3 high severity vulnerabilities
```

Note the useful detail in that output: `multer <=2.2.0` is affected, and the
remediation `npm audit fix --force` wants to apply is `multer@2.4.0` — a
**breaking major upgrade**, which is exactly why a demo lab should never be
upgraded by accident.

### Remediation

```console
$ cd server
$ npm install multer@^2.4.0
```

Multer 2.x is a breaking change (`busboy` 1.x, stricter `fileFilter` contract,
`diskStorage` signature changes), so `server/src/routes/files.ts` must be
re-checked after the bump. Do **not** apply this in the demo lab unless you are
demonstrating the fix — the outdated pin is part of the scenario.

---

## VULN-014 — Fake secrets committed in `config/demo.env`

`config/demo.env` is a deliberately discoverable secret file:

```
DEMO_API_KEY=demo_secret_123
DEMO_DB_PASSWORD=demo_password
DEMO_JWT_SECRET=demo_jwt_secret_not_for_production
DEMO_REDIS_PASSWORD=demo_redis_pass_456
DEMO_SERVICE_TOKEN=demo_service_token_789
DEMO_ENCRYPTION_KEY=demo_encryption_key_abcdef123456
```

| Field | Value |
|---|---|
| CWE | CWE-540 (Use of Hard-Coded Password) / CWE-798 |
| OWASP | A05:2021 Security Misconfiguration |
| MITRE ATT&CK | T1552.001 Credentials In Files |

Reproduce with any secret scanner or plain search:

```console
$ grep -rn "DEMO_API_KEY\|demo_encryption_key" .
config/demo.env:5:DEMO_API_KEY=demo_secret_123
config/demo.env:10:DEMO_ENCRYPTION_KEY=demo_encryption_key_abcdef123456
```

**Every value above is fake.** They exist so that a scanner has something
concrete to find, and so that the SSRF demo
(`http://internal-service:8080/internal/demo-secret` → `demo_internal_secret_123`)
has a harmless target. The real JWT secrets are supplied through the
`JWT_SECRET` / `JWT_REFRESH_SECRET` environment variables in `docker-compose.yml`
— never from a file.

`config/secure.env` is the remediation target named by the finding: a committed
template with placeholders only and instructions to generate fresh values.

---

## Related scanning entry points

| What | Where |
|---|---|
| Machine-readable vulnerability catalog | `GET /api/security/findings` |
| Machine-readable SOC detection rules | `GET /api/security/detection-rules` |
| Machine-readable attack scenarios | `GET /api/security/scenarios` |
| Raw security telemetry | `GET /api/security/events` |
| Demo scenario walkthrough | `docs/HACKATHON-DEMO.md` |
| Full catalog and mapping tables | `README.md` |