# AI-Generated Fix Pull Requests

The most literal version of "AI security engineer that fixes things," taken as far as is safe to take it: instead of only flipping a runtime toggle, SentinelForge can open a **real pull request** against the real CyberLab source, with an AI-written description, for a human to review and merge.

## Why the code patch itself isn't AI-generated

`RemediationAgent` (AI) writes the PR's root-cause/secure-approach/tests/verification text from real evidence — that part is genuinely model output (or the offline equivalent). The literal code change applied to the file is **deterministic**, taken from a small registry (`modules/remediation/patches.ts`) of known-correct patches, one per supported vuln key.

This is a deliberate safety choice, not a shortcut: having a model generate arbitrary code changes to a real repository, with nobody reviewing the diff before it's committed, is a real way to introduce broken or subtly-wrong code with no safety net. Since CyberLab already ships a hand-written, proven-correct secure implementation for every supported endpoint (the same logic its lab-fix runtime toggle switches to — see `docs/REMEDIATION.md`), the patch applies that exact logic as real source code instead of a route rewrite. The honest framing: **AI-reviewed, deterministically applied** — the AI explains why and writes the PR description from real evidence; a human still reviews and merges the actual diff on GitHub.

## Flow

```
POST /api/findings/:id/open-pr
  1. RemediationAgent runs (real AI call, same as "Generate Remediation")
  2. modules/remediation/githubPr.ts:
     - checks out a new branch: sentinelforge-autofix/<vulnkey>-<timestamp>
     - applies the known patch to the one target file
     - git add <that file only> / commit / push
     - gh pr create, with the AI's plan as the PR body
     - returns to the original branch
  3. RemediationTask stored with the PR URL
```

Only the one target file is ever staged or committed — never `git add -A`/`git commit -a` — so any other uncommitted work in the repo (the entire rest of this build, in practice) is untouched.

## Requires host filesystem + git access

This only works when the backend process can see the actual repository checkout and has `git`/`gh` on PATH — i.e. **host dev mode** (`npm run dev`), not the dockerized backend (the container has no copy of the repo or `.git`). Calling it against the dockerized backend returns a clear `RepoUnavailableError` (400), not a crash.

## Verified live — and a real bug found and fixed

Ran for real against `VULN-001`: opened **https://github.com/siddhuthecoder/Hackthon-project/pull/1**, a genuine PR with the AI-written description and the real patch to `cyberlab/server/src/routes/users.ts`.

A real bug surfaced during this test: the final "return to the original branch" step failed with `fatal: unable to update HEAD` — a transient Windows issue (something briefly held `.git/HEAD` open during git's atomic ref-rename, observed once, not reproduced on retry) — and the original code **silently swallowed** that failure, leaving the repository checked out on the new feature branch with no indication anything was wrong. Fixed properly: one retry, and if that also fails, the error is logged loudly rather than hidden, so this situation is never silently missed again. Confirmed afterward that the working tree content itself was correct throughout (the file content matched `main`'s version even while `HEAD` briefly pointed at the wrong ref) — no data was at risk, but the silent-failure *handling* was a real defect, now fixed.

## Coverage

Patches registered for `VULN-001` and `VULN-002` (`modules/remediation/patches.ts`) — enough to prove the mechanism works end to end. Calling `open-pr` for a vuln key without a registered patch returns a clear `PatchUnavailableError` (400) rather than attempting something undefined.

## Safety

- Never auto-merges — opens the PR only, review/merge stays a human GitHub action.
- Requires `apply_fix` permission (admin/analyst), same trust level as applying the runtime fix toggle.
- This action pushes to and opens a PR on a real, outward-facing repository — it was only run after explicit confirmation from the repo owner, and the harness's own connected-app safety classifier independently flagged it for confirmation before it executed.
