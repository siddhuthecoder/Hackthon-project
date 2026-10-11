import { ISecurityEvent } from '../../db/models';

export interface RuleMatch {
  rule: string;
  title: string;
  subject: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  sourceIp?: string;
  users: string[];
  assets: string[];
  eventIds: string[];
  findings: string[];
  mitre: string;
  recommendedActions: string[];
}

function groupBy<T>(items: readonly T[], keyFn: (item: T) => string | null | undefined): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const key = keyFn(item);
    if (!key) continue;
    const bucket = groups.get(key);
    if (bucket) bucket.push(item);
    else groups.set(key, [item]);
  }
  return groups;
}

function dominantIp(events: readonly ISecurityEvent[]): string | undefined {
  const counts = new Map<string, number>();
  for (const e of events) if (e.sourceIp) counts.set(e.sourceIp, (counts.get(e.sourceIp) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
}

type RuleEvaluator = (events: readonly ISecurityEvent[]) => RuleMatch[];

const bruteForce: RuleEvaluator = events => {
  const failures = events.filter(e => e.eventType === 'AUTH_FAILURE');
  const out: RuleMatch[] = [];
  for (const [ip, group] of groupBy(failures, e => e.sourceIp)) {
    if (group.length <= 10) continue;
    out.push({
      rule: 'RULE-001', title: 'Brute Force Attack Detected', subject: ip, severity: 'high', confidence: 0.85,
      sourceIp: ip, users: [], assets: ['/api/auth/login'], eventIds: group.map(e => e._id), findings: ['VULN-009'],
      mitre: 'T1110 Brute Force', recommendedActions: ['Block source IP', 'Force password reset', 'Enable MFA'],
    });
  }
  return out;
};

const accountTakeover: RuleEvaluator = events => {
  // Many failed logins from an IP, followed by a success from that same IP (not necessarily the
  // same user the failures targeted — that's exactly what credential-stuffing looks like).
  const out: RuleMatch[] = [];
  for (const [ip, group] of groupBy(events, e => e.sourceIp)) {
    const failures = group.filter(e => e.eventType === 'AUTH_FAILURE');
    if (failures.length <= 5) continue;
    const lastFailureAt = Math.max(...failures.map(f => f.timestamp.getTime()));
    const successes = group.filter(e => e.eventType === 'AUTH_SUCCESS' && e.timestamp.getTime() >= lastFailureAt);
    if (successes.length === 0) continue;
    const evidence = [...failures, ...successes];
    out.push({
      rule: 'RULE-002', title: 'Possible Account Takeover', subject: ip, severity: 'critical', confidence: 0.92,
      sourceIp: ip, users: [...new Set(successes.map(e => e.userId).filter((u): u is string => Boolean(u)))],
      assets: ['/api/auth/login'], eventIds: evidence.map(e => e._id), findings: ['VULN-009'],
      mitre: 'T1078 Valid Accounts',
      recommendedActions: ['Revoke the new session', 'Force password reset', 'Notify the affected user', 'Enable MFA'],
    });
  }
  return out;
};

const idorEnumeration: RuleEvaluator = events => {
  const reads = events.filter(e => e.eventType === 'DATA_ACCESS' && e.userId && e.metadata?.resourceType === 'user');
  const out: RuleMatch[] = [];
  for (const [userId, group] of groupBy(reads, e => e.userId)) {
    const distinctIds = new Set(group.map(e => (e.metadata as { resourceId?: string })?.resourceId).filter(Boolean));
    if (distinctIds.size <= 5) continue;
    out.push({
      rule: 'RULE-003', title: 'Possible IDOR Attack', subject: userId, severity: 'high', confidence: 0.85,
      sourceIp: dominantIp(group), users: [userId], assets: ['/api/users/:userId'], eventIds: group.map(e => e._id),
      findings: ['VULN-001'], mitre: 'T1087 Account Discovery',
      recommendedActions: ['Revoke session', 'Audit object-level authorization', 'Verify fix on affected endpoint'],
    });
  }
  return out;
};

const crossTenant: RuleEvaluator = events => {
  const hits = events.filter(e => e.eventType === 'CROSS_TENANT_ACCESS_ATTEMPT');
  const out: RuleMatch[] = [];
  for (const [userId, group] of groupBy(hits, e => e.userId)) {
    out.push({
      rule: 'RULE-004', title: 'Cross-Tenant Data Access Attempt', subject: userId, severity: 'critical', confidence: 0.92,
      sourceIp: dominantIp(group), users: [userId], assets: [group[0].endpoint ?? '/api/orders/:orderId'],
      eventIds: group.map(e => e._id), findings: ['VULN-002'], mitre: 'T1530 Data from Cloud Storage',
      recommendedActions: ['Revoke session', 'Audit cross-tenant access', 'Verify fix on affected endpoint'],
    });
  }
  return out;
};

const privilegeEscalation: RuleEvaluator = events => {
  const lowRoles = ['USER', 'STAFF'];
  const adminRoles = ['TENANT_ADMIN', 'SUPER_ADMIN'];
  const hits = events.filter(e => {
    const m = e.metadata as { oldRole?: string; newRole?: string } | undefined;
    return e.eventType === 'PRIVILEGE_CHANGE' && m && lowRoles.includes(m.oldRole ?? '') && adminRoles.includes(m.newRole ?? '');
  });
  const out: RuleMatch[] = [];
  for (const [userId, group] of groupBy(hits, e => e.userId)) {
    out.push({
      rule: 'RULE-005', title: 'Privilege Escalation via Mass Assignment', subject: userId, severity: 'critical', confidence: 0.9,
      sourceIp: dominantIp(group), users: [userId], assets: ['/api/users/:id'], eventIds: group.map(e => e._id),
      findings: ['VULN-011'], mitre: 'T1098 Account Manipulation',
      recommendedActions: ['Revoke elevated session', 'Audit role change history', 'Verify fix on affected endpoint'],
    });
  }
  return out;
};

const dataExfiltration: RuleEvaluator = events => {
  const hits = events.filter(e => e.eventType === 'BULK_DATA_ACCESS');
  const out: RuleMatch[] = [];
  for (const [userId, group] of groupBy(hits, e => e.userId)) {
    const totalRecords = group.reduce((sum, e) => sum + (Number((e.metadata as { recordCount?: number })?.recordCount) || 0), 0);
    if (totalRecords < 100 && group.length < 3) continue;
    out.push({
      rule: 'RULE-006', title: 'Possible Data Exfiltration', subject: userId, severity: 'critical', confidence: 0.8,
      sourceIp: dominantIp(group), users: [userId], assets: ['/api/orders/export'], eventIds: group.map(e => e._id),
      findings: [], mitre: 'T1530 Data from Cloud Storage',
      recommendedActions: ['Revoke session', 'Audit exported records', 'Review export rate limits'],
    });
  }
  return out;
};

// Unlike every other rule, a single hit is already certain — there is no legitimate reason for
// any real caller (user, scanner, automated client) to ever reach one of these endpoints, so no
// threshold/count logic is needed. See cyberlab/server/src/routes/canary.ts.
const canaryTriggered: RuleEvaluator = events => {
  const hits = events.filter(e => e.eventType === 'CANARY_TRIGGERED');
  const out: RuleMatch[] = [];
  for (const [ip, group] of groupBy(hits, e => e.sourceIp)) {
    out.push({
      rule: 'RULE-007', title: 'Canary/Deception Endpoint Triggered', subject: ip, severity: 'critical', confidence: 1.0,
      sourceIp: ip, users: [], assets: group.map(e => e.endpoint).filter((a): a is string => Boolean(a)),
      eventIds: group.map(e => e._id), findings: [], mitre: 'T1595 Active Scanning',
      recommendedActions: ['Block source IP immediately', 'Review all other activity from this IP', 'This is a bait endpoint — any hit is confirmed malicious, not a false positive'],
    });
  }
  return out;
};

export const RULES: RuleEvaluator[] = [bruteForce, accountTakeover, idorEnumeration, crossTenant, privilegeEscalation, dataExfiltration, canaryTriggered];
