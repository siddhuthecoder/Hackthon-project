/**
 * Real PDF report generation (pdfkit — pure JS, no headless browser needed). Every value written
 * here comes from a real DB record passed in by the caller; nothing is templated with placeholder
 * text. Enterprise-readiness feature: a security finding or incident needs to leave the app as a
 * shareable document (compliance evidence, a ticket attachment, something to email) at some point.
 */
import PDFDocument from 'pdfkit';
import { IIncident, ICorrelation, ISecurityEvent, IVulnerability } from '../../db/models';
import { RiskScore } from '../findings/risk';

function streamToBuffer(doc: PDFKit.PDFDocument): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    doc.on('data', chunk => chunks.push(chunk as Buffer));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });
}

function header(doc: PDFKit.PDFDocument, title: string, subtitle: string): void {
  doc.fontSize(20).fillColor('#0f172a').text('SentinelForge AI', { continued: false });
  doc.fontSize(10).fillColor('#64748b').text('Autonomous Security Engineer — Report', { continued: false });
  doc.moveDown(1);
  doc.fontSize(16).fillColor('#0f172a').text(title);
  doc.fontSize(10).fillColor('#64748b').text(subtitle);
  doc.moveDown(1);
  doc.strokeColor('#e2e8f0').moveTo(doc.x, doc.y).lineTo(560, doc.y).stroke();
  doc.moveDown(1);
}

function section(doc: PDFKit.PDFDocument, title: string, body: string): void {
  doc.fontSize(12).fillColor('#0f172a').text(title, { underline: false });
  doc.fontSize(10).fillColor('#334155').text(body || '—');
  doc.moveDown(0.8);
}

function list(doc: PDFKit.PDFDocument, title: string, items: string[]): void {
  if (!items || items.length === 0) return;
  doc.fontSize(12).fillColor('#0f172a').text(title);
  doc.fontSize(10).fillColor('#334155').list(items);
  doc.moveDown(0.8);
}

export async function buildFindingReportPdf(finding: IVulnerability): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 50, bufferPages: true });
  const done = streamToBuffer(doc);

  header(doc, `${finding.vulnKey} — ${finding.title}`, `Severity: ${finding.severity.toUpperCase()} · Status: ${finding.status} · Generated ${new Date().toISOString()}`);
  section(doc, 'Classification', `${finding.cwe ?? 'No CWE'} · ${finding.owasp ?? 'No OWASP classification'} · Affected: ${finding.method} ${finding.endpoint}`);
  section(doc, 'Description', finding.description);
  section(doc, 'Impact', finding.impact);
  section(doc, 'Remediation', finding.remediation);

  const analysis = finding.aiAnalysis as { summary?: string; facts?: string[]; inferences?: string[]; uncertainties?: string[]; mode?: string } | undefined;
  if (analysis) {
    doc.fontSize(12).fillColor('#0f172a').text(`AI Analysis (mode: ${analysis.mode ?? 'unknown'})`);
    doc.fontSize(10).fillColor('#334155').text(analysis.summary ?? '');
    doc.moveDown(0.4);
    list(doc, 'Facts', analysis.facts ?? []);
    list(doc, 'Inferences', analysis.inferences ?? []);
    list(doc, 'Uncertainties', analysis.uncertainties ?? []);
  }

  const evidence = finding.evidence as { summary?: string };
  section(doc, 'Scanner Evidence', evidence?.summary ?? JSON.stringify(finding.evidence));

  doc.end();
  return done;
}

export interface ExecutiveSummaryInput {
  organizationName: string;
  severityCounts: Record<string, number>;
  avgTimeToFixHours: number | null;
  findingsVerified: number;
  scanHistoryCount: number;
  topRisks: { vulnKey: string; title: string; severity: string; applicationName: string; risk: RiskScore }[];
}

/** A single CISO-facing page — posture score, top risks, trend summary, time-to-fix — auto-
 * assembled from /api/metrics/posture + /api/findings/prioritized, as opposed to the per-finding
 * report above which someone exports one at a time. */
export async function buildExecutiveSummaryPdf(input: ExecutiveSummaryInput): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 50, bufferPages: true });
  const done = streamToBuffer(doc);

  header(doc, 'Executive Security Summary', `${input.organizationName} · Generated ${new Date().toISOString()}`);

  const totalOpen = Object.values(input.severityCounts).reduce((a, b) => a + b, 0);
  section(doc, 'Current Posture', `${totalOpen} open finding(s) — critical: ${input.severityCounts.critical ?? 0}, high: ${input.severityCounts.high ?? 0}, medium: ${input.severityCounts.medium ?? 0}, low: ${input.severityCounts.low ?? 0}.`);
  section(doc, 'Remediation Velocity', input.avgTimeToFixHours != null
    ? `Average time to fix (detection → verified): ${Math.round(input.avgTimeToFixHours * 10) / 10} hours, across ${input.findingsVerified} verified finding(s).`
    : 'No findings have been verified as fixed yet.');
  section(doc, 'Monitoring', `${input.scanHistoryCount} completed scan run(s) recorded.`);

  doc.fontSize(12).fillColor('#0f172a').text('Top 5 Risks (fix these first)');
  doc.moveDown(0.3);
  for (const risk of input.topRisks.slice(0, 5)) {
    doc.fontSize(10).fillColor('#334155').text(
      `${risk.vulnKey} — ${risk.title} (${risk.severity.toUpperCase()}, ${risk.applicationName}) — risk score ${risk.risk.score}/100 ` +
      `[severity ${risk.risk.breakdown.severity} + EPSS ${risk.risk.breakdown.epss} + KEV ${risk.risk.breakdown.kev} + exposure ${risk.risk.breakdown.exposure}]`,
    );
  }
  if (input.topRisks.length === 0) doc.fontSize(10).fillColor('#334155').text('No open findings.');

  doc.end();
  return done;
}

export async function buildIncidentReportPdf(
  incident: IIncident,
  events: ISecurityEvent[],
  correlations: ICorrelation[],
  findings: IVulnerability[],
): Promise<Buffer> {
  const doc = new PDFDocument({ margin: 50, bufferPages: true });
  const done = streamToBuffer(doc);

  header(doc, incident.title, `Severity: ${incident.severity.toUpperCase()} · Status: ${incident.status} · Detected ${incident.detectedAt.toISOString()}`);
  section(doc, 'Detection', `Rule ${incident.rule} · Subject ${incident.subject} · Source IP ${incident.sourceIp ?? 'unknown'} · Confidence ${Math.round(incident.confidence * 100)}%`);

  if (correlations.length > 0) {
    doc.fontSize(12).fillColor('#0f172a').text('Correlated Known Vulnerabilities');
    for (const c of correlations) {
      const f = findings.find(x => x._id === c.findingId);
      doc.fontSize(10).fillColor('#334155').text(`${f?.vulnKey ?? c.findingId}: ${c.reason}`);
    }
    doc.moveDown(0.8);
  }

  const investigation = incident.investigation as { summary?: string; attackPath?: string; impact?: string; recommendedActions?: string[]; mode?: string } | undefined;
  if (investigation) {
    doc.fontSize(12).fillColor('#0f172a').text(`AI Investigation (mode: ${investigation.mode ?? 'unknown'})`);
    doc.fontSize(10).fillColor('#334155').text(investigation.summary ?? '');
    doc.moveDown(0.4);
    section(doc, 'Attack Path', investigation.attackPath ?? '');
    section(doc, 'Impact', investigation.impact ?? '');
    list(doc, 'Recommended Actions', investigation.recommendedActions ?? []);
  }

  list(doc, 'Recommended Actions (rule-based)', incident.recommendedActions);

  doc.fontSize(12).fillColor('#0f172a').text(`Event Timeline (${events.length} events)`);
  doc.fontSize(9).fillColor('#334155');
  for (const e of events.slice(0, 40)) {
    doc.text(`${e.timestamp.toISOString()}  ${e.eventType}${e.endpoint ? `  ${e.endpoint}` : ''}`);
  }
  if (events.length > 40) doc.text(`… and ${events.length - 40} more events (truncated for report length)`);

  doc.end();
  return done;
}
