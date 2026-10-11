import { execFile } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { promisify } from 'util';
import { IVulnerability } from '../../db/models';
import { RemediationPlan } from '../ai/remediate';
import { findPatch } from './patches';

const execFileAsync = promisify(execFile);

export class PatchUnavailableError extends Error {}
export class RepoUnavailableError extends Error {}

// The repo root, relative to this compiled file's location (dist/modules/remediation ->
// sentinelforge/backend/dist/modules/remediation -> up 4 levels is the repo root). Overridable
// via env for environments where that doesn't hold (e.g. a different checkout layout). This
// feature only works when the backend can see the actual git checkout — i.e. host dev mode, not
// the dockerized backend (the container has no copy of the repository or .git directory).
const REPO_ROOT = process.env.SF_REPO_ROOT || path.resolve(__dirname, '../../../../../');

async function git(args: string[], cwd: string = REPO_ROOT): Promise<string> {
  const { stdout } = await execFileAsync('git', args, { cwd });
  return stdout.trim();
}

async function gh(args: string[], cwd: string = REPO_ROOT): Promise<string> {
  const { stdout } = await execFileAsync('gh', args, { cwd });
  return stdout.trim();
}

export interface OpenedPr {
  url: string;
  branch: string;
  file: string;
}

/**
 * Applies the known-correct patch for `finding.vulnKey` to the real file in the real repository,
 * on a new branch, and opens a real GitHub PR with the AI-written explanation as the description.
 * Never touches `main`/the working branch's other uncommitted changes — only the one target file
 * is staged and committed. Leaves the repo back on its original branch when done.
 */
export async function openRemediationPr(finding: IVulnerability, plan: RemediationPlan, actor: string): Promise<OpenedPr> {
  const patch = findPatch(finding.vulnKey);
  if (!patch) {
    throw new PatchUnavailableError(`No real-PR patch registered for ${finding.vulnKey} yet (see modules/remediation/patches.ts).`);
  }

  const filePath = path.join(REPO_ROOT, patch.file);
  let original: string;
  try {
    original = await fs.readFile(filePath, 'utf8');
  } catch (err) {
    throw new RepoUnavailableError(`Could not read ${patch.file} — this feature requires the backend to run with access to the actual repository checkout (host dev mode, not the dockerized backend). ${err instanceof Error ? err.message : ''}`);
  }
  if (!original.includes(patch.find)) {
    throw new PatchUnavailableError(`${patch.file} no longer matches the expected vulnerable pattern for ${finding.vulnKey} (already patched, or the source has changed).`);
  }

  const originalBranch = await git(['rev-parse', '--abbrev-ref', 'HEAD']);
  const branch = `sentinelforge-autofix/${finding.vulnKey.toLowerCase()}-${Date.now()}`;

  try {
    await git(['checkout', '-b', branch]);
    const patched = original.replace(patch.find, patch.replace);
    await fs.writeFile(filePath, patched, 'utf8');
    await git(['add', patch.file]);
    await git(['commit', '-m', `fix(${finding.vulnKey.toLowerCase()}): ${plan.patchSummary}\n\nOpened automatically by SentinelForge's RemediationAgent.\nRoot cause: ${plan.rootCause}\nSecure approach: ${plan.secureApproach}`]);
    await git(['push', '-u', 'origin', branch]);

    const body = [
      `**Automated fix from SentinelForge AI** for \`${finding.vulnKey}\`: ${finding.title}`,
      '',
      `**Root cause**\n${plan.rootCause}`,
      '',
      `**Secure approach**\n${plan.secureApproach}`,
      '',
      '**Tests required**',
      ...plan.testsRequired.map(t => `- [ ] ${t}`),
      '',
      '**Verification steps**',
      ...plan.verificationSteps.map(v => `- [ ] ${v}`),
      '',
      `Requested by: ${actor}`,
      '',
      '_This PR was opened automatically. Review and merge is a human decision — nothing here auto-merges._',
    ].join('\n');

    const prUrl = await gh(['pr', 'create', '--title', `fix(${finding.vulnKey}): ${finding.title}`, '--body', body, '--head', branch]);

    return { url: prUrl, branch, file: patch.file };
  } finally {
    // Always try to return to the branch we started on, regardless of success or failure, so the
    // repo is never left mid-feature-branch. `git checkout` can fail transiently on Windows (an
    // antivirus/indexer briefly holding .git/HEAD open during the atomic ref rename — observed
    // live during testing: "fatal: unable to update HEAD" with no actual conflict). One retry
    // covers that; if it still fails, surface it loudly instead of silently leaving the repo on
    // the autofix branch — a swallowed failure here is a real, confusing state for a human to
    // find later, not a safe thing to hide.
    try {
      await git(['checkout', originalBranch]);
    } catch {
      try {
        await git(['checkout', originalBranch]);
      } catch (err) {
        console.error(`[githubPr] Could not switch back to '${originalBranch}' after opening the PR. The repo is left on '${branch}'. Run "git checkout ${originalBranch}" manually.`, err);
      }
    }
  }
}
