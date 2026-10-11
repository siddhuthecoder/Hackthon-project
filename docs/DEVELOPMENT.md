# Local Development

## Prerequisites

- Node.js 20+, npm
- Docker Desktop (for CyberLab)
- A local MongoDB (the backend connects to `mongodb://127.0.0.1:27017/sfplatform` by default — this can be a host install or any reachable Mongo instance; it is deliberately **not** the same Mongo that CyberLab's own container uses, see `docs/DATABASE.md`)
- `gitleaks` on `PATH` — only if running the backend via `npm run dev` (not Docker). The dockerized backend ships it baked in (see `sentinelforge/backend/Dockerfile`). Used by the VULN-014 check and its verify probe (`modules/scanner/gitleaks.ts`); install from [github.com/gitleaks/gitleaks/releases](https://github.com/gitleaks/gitleaks/releases).

## Environment variables

Three separate `.env` files, all gitignored:

| File | Required vars |
|---|---|
| `cyberlab/.env` | `LAB_CONTROL_KEY` (generate: `node -e "console.log(require('crypto').randomBytes(24).toString('hex'))"`) |
| `sentinelforge/backend/.env` | `SF_JWT_SECRET`, `SF_ADMIN_PASSWORD`, `SF_ANALYST_PASSWORD`, `LAB_CONTROL_KEY` (must match `cyberlab/.env`), `CYBERLAB_JWT_SECRET` (= CyberLab's own `JWT_SECRET` from `cyberlab/docker-compose.yml`), `MONGODB_URI` (optional, has a sane default), `ANTHROPIC_API_KEY` (optional — offline mode without it) |
| `sentinelforge/frontend/.env.local` | `NEXT_PUBLIC_API_URL` (default `http://localhost:4000`) |

Each has a committed `.env.example` listing names only.

## Database setup

No migrations to run — Mongoose creates collections on first write. Run `npm run seed` once (in `sentinelforge/backend`) to create the admin/analyst accounts.

## Docker setup

CyberLab: `cd cyberlab && docker compose up -d` (brings up its own MongoDB, Redis, API, worker, internal-service, frontend, nginx).

SentinelForge backend + frontend currently run via `npm run dev`, not containerized (see `docs/IMPLEMENTATION-STATUS.md` known gaps / `sentinelforge/docker-compose.yml` + `Dockerfile`s if present for the containerized path).

## Development mode

```bash
# terminal 1
cd cyberlab && docker compose up -d

# terminal 2
cd sentinelforge/backend
npm install
npm run seed
npm run dev        # tsx watch, http://localhost:4000

# terminal 3
cd sentinelforge/frontend
npm install
npm run dev        # http://localhost:3000
```

## Testing

```bash
cd sentinelforge/backend
npm run typecheck    # tsc --noEmit
npm run test:e2e     # full live hero-flow check, 13 steps
```

There is no unit test suite yet (see `docs/IMPLEMENTATION-STATUS.md` known gaps) — `test:e2e` is the only automated check, and it's run against the real live stack, not mocks.

## Demo reset

```bash
cd sentinelforge/backend
npm run demo:reset
```

## Demo execution

See `docs/HACKATHON-DEMO.md` for the full script.

## Code layout conventions

- One module per concern under `src/modules/<name>/{routes.ts, service.ts}` — routes stay thin (validate, call service, respond); logic lives in `service.ts`.
- Every Mongoose model gets an explicit TypeScript interface (`db/models.ts`) — Mongoose's automatic inference proved unreliable for several fields during development (surfaced as confusing `NativeDate`-shaped type errors); explicit interfaces avoid that entirely.
- No `any` in application code; `unknown` + narrowing for external data (API responses, request bodies before zod validation).
- Secrets: never a literal default in code. If a value looks like a password/key/token, it comes from `process.env` with no fallback, or the function that needs it throws a clear error.
