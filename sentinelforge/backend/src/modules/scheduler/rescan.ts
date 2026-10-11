/**
 * Recurring re-scan — the "continuous monitoring" real posture-management tools (Snyk, Qualys)
 * run as their default mode, instead of scan-only-on-click. Same setInterval pattern as
 * modules/live/loop.ts (no new dependency). Only applications with scanIntervalMinutes set are
 * touched; manual-trigger-only applications are left alone. Each due re-scan reuses the exact
 * same scan functions (runScan/runJuiceShopScan/runGenericScan) the manual "Run Scan" button
 * calls, so there is exactly one scan pipeline, not a duplicated scheduled-only path.
 */
import { config } from '../../config';
import { Application, ScanRun } from '../../db/models';
import { CyberLabAdapter } from '../cyberlab/adapter';
import { runGenericScan, runJuiceShopScan, runScan } from '../scanner/service';
import { GenericAdapter } from '../targets/generic/adapter';
import { JuiceShopAdapter } from '../targets/juiceshop/adapter';

let timer: NodeJS.Timeout | undefined;

export function startRescanScheduler(): void {
  if (timer) return;
  timer = setInterval(tick, config.scheduler.checkIntervalMs);
}

export function stopRescanScheduler(): void {
  if (timer) clearInterval(timer);
  timer = undefined;
}

async function tick(): Promise<void> {
  const applications = await Application.find({ scanIntervalMinutes: { $gt: 0 }, status: { $ne: 'REGISTERED' } });
  for (const application of applications) {
    try {
      if (await isDue(application.id, application.scanIntervalMinutes!)) {
        await rescan(application);
      }
    } catch (err) {
      // One application's scheduled scan failing (target briefly down) must never stop the rest.
      console.error(`[scheduler] rescan failed for ${application.id} (non-fatal):`, err instanceof Error ? err.message : err);
    }
  }
}

async function isDue(applicationId: string, intervalMinutes: number): Promise<boolean> {
  const lastRun = await ScanRun.findOne({ applicationId, status: 'COMPLETED' }).sort({ startedAt: -1 });
  if (!lastRun) return true;
  return Date.now() - lastRun.startedAt.getTime() >= intervalMinutes * 60 * 1000;
}

async function rescan(application: { id: string; adapter: string; baseUrl: string; name: string; config: Record<string, unknown> }): Promise<void> {
  if (application.adapter === 'juiceshop') {
    await runJuiceShopScan(application.id, new JuiceShopAdapter(application.baseUrl), 'scheduler', application.name);
  } else if (application.adapter === 'generic') {
    await runGenericScan(application.id, new GenericAdapter(application.baseUrl, application.config), 'scheduler', application.name);
  } else {
    await runScan(application.id, new CyberLabAdapter(application.baseUrl), 'scheduler', application.name);
  }
}
