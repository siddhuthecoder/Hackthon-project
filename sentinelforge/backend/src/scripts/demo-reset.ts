import { config } from '../config';
import { connectDb, disconnectDb } from '../db/connection';
import {
  Application, Asset, AttackPath, Correlation, Detection, Endpoint, Incident,
  RemediationTask, ResponseAction, ScanResult, ScanRun, SecurityEvent, VerificationRun, Vulnerability,
} from '../db/models';
import { CyberLabAdapter } from '../modules/cyberlab/adapter';

/**
 * Resets SentinelForge's own data (keeps organizations/users so you don't need to re-seed
 * credentials) and resets CyberLab's lab-fix toggles so the vulnerable endpoints are live again.
 * Does NOT touch CyberLab's own database — run `npm run reset` inside cyberlab/server for that.
 */
async function main(): Promise<void> {
  await connectDb();

  const clear = async (name: string, deleteAll: () => Promise<{ deletedCount?: number }>): Promise<void> => {
    const res = await deleteAll();
    console.log(`[reset] cleared ${name}: ${res.deletedCount ?? 0}`);
  };

  await clear('applications', () => Application.deleteMany({}));
  await clear('assets', () => Asset.deleteMany({}));
  await clear('endpoints', () => Endpoint.deleteMany({}));
  await clear('scan_runs', () => ScanRun.deleteMany({}));
  await clear('scan_results', () => ScanResult.deleteMany({}));
  await clear('vulnerabilities', () => Vulnerability.deleteMany({}));
  await clear('security_events', () => SecurityEvent.deleteMany({}));
  await clear('detections', () => Detection.deleteMany({}));
  await clear('incidents', () => Incident.deleteMany({}));
  await clear('correlations', () => Correlation.deleteMany({}));
  await clear('attack_paths', () => AttackPath.deleteMany({}));
  await clear('remediation_tasks', () => RemediationTask.deleteMany({}));
  await clear('verification_runs', () => VerificationRun.deleteMany({}));
  await clear('response_actions', () => ResponseAction.deleteMany({}));

  try {
    const lab = new CyberLabAdapter(config.cyberlab.baseUrl);
    await lab.resetFixes();
    console.log('[reset] CyberLab lab-fix toggles reset (all vulnerabilities live again)');
  } catch (err) {
    console.warn('[reset] could not reset CyberLab lab-fix state:', err instanceof Error ? err.message : err);
  }

  console.log('[reset] done. Re-run: register application -> discover -> scan -> simulate.');
  await disconnectDb();
}

main().catch(err => {
  console.error('[reset] failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
