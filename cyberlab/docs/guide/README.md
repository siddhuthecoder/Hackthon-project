# Beginner Guide to the SentinelForge Vulnerable Cybersecurity Demo Lab

Written for a developer who knows programming but has never studied cybersecurity.

Read in order:

1. [Concepts, purpose, architecture, users and authentication](01-concepts-and-architecture.md)
   - security vocabulary, what the lab is (and is not), why it exists, the 7 containers, tenants, roles, data, JWT/sessions
2. [Every vulnerability, with commands you can run](02-vulnerabilities.md)
   - VULN-001 to VULN-014 plus the outdated dependency, each with what/why/where/reproduce/evidence/fix/detection
3. [Events, SOC rules, simulators, incidents, attack graph, pages, demo flow, glossary, one-page summary](03-soc-demo-glossary.md)

Quick start:

```bash
docker compose up -d --build
./scripts/seed.sh
open http://localhost        # UI
./scripts/simulate/03-idor.sh # run an attack, then look at /incidents
./tests/run.sh                # prove everything still works (77 tests)
```

Everything is local, fake and sandboxed. See the safety notes in the main `README.md`.
