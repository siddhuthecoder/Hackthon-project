/**
 * Real-time external alerting on incident creation. Uses the generic "incoming webhook" JSON
 * shape ({"text": "..."}) that Slack, Discord-via-Slack-compat-mode, and most webhook relays all
 * accept — no Slack-specific SDK needed, just a plain POST. Configured via WEBHOOK_URL; if unset,
 * this is a complete no-op (never blocks or slows the detection pipeline it's called from).
 */
import { config } from '../../config';
import { IIncident } from '../../db/models';

async function postWebhook(text: string): Promise<void> {
  if (!config.notifications.webhookUrl) return;
  try {
    await fetch(config.notifications.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
  } catch (err) {
    // A webhook outage must never affect the pipeline that triggered it.
    console.error('[webhook] failed to send notification (non-fatal):', err instanceof Error ? err.message : err);
  }
}

export async function notifyIncidentCreated(incident: IIncident): Promise<void> {
  const severityEmoji: Record<string, string> = { low: '🔵', medium: '🟡', high: '🟠', critical: '🔴' };
  const text = [
    `${severityEmoji[incident.severity] ?? '⚪'} *New incident: ${incident.title}*`,
    `Severity: *${incident.severity.toUpperCase()}* · Rule: \`${incident.rule}\` · Subject: \`${incident.subject}\``,
    incident.sourceIp ? `Source IP: \`${incident.sourceIp}\`` : undefined,
    `Detected: ${incident.detectedAt.toISOString()}`,
  ].filter(Boolean).join('\n');
  await postWebhook(text);
}

/** The autonomous SOAR playbook (modules/autonomy/soar.ts) fired — a distinct, louder alert than
 * a routine incident notification, since it means the system judged this risky enough to act on
 * its own (ticket + staged response action) without a human triggering anything. */
export async function notifyPlaybookTriggered(
  incidentTitle: string, vulnKey: string, riskScore: number, ticketUrl: string | undefined, actionStaged: boolean,
): Promise<void> {
  const text = [
    `🤖 *Autonomous SOAR playbook triggered* — ${incidentTitle}`,
    `Risk score ${riskScore}/100 via ${vulnKey}.`,
    ticketUrl ? `Jira ticket: ${ticketUrl}` : 'Jira ticket: not created (not configured).',
    actionStaged ? 'A block_ip action has been staged — needs human approval.' : 'No source IP recorded, no action staged.',
  ].join('\n');
  await postWebhook(text);
}

/** A vulnerability that was fixed-and-verified reappeared on a later scan — a real regression,
 * not a routine finding, so it gets its own distinct alert rather than blending into the normal
 * scan-completed noise. See modules/scanner/diff.ts for how "regressed" is determined. */
export async function notifyRegressionDetected(applicationName: string, vulnKeys: string[]): Promise<void> {
  const text = [
    `🔺 *Regression detected on ${applicationName}*`,
    `Previously fixed and verified, now vulnerable again: \`${vulnKeys.join('`, `')}\``,
  ].join('\n');
  await postWebhook(text);
}
