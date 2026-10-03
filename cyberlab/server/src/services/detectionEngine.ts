import { SecurityEvent } from '../models/SecurityEvent';
import { Incident } from '../models/Incident';
import { AttackGraph } from '../models/AttackGraph';
import { v4 as uuidv4 } from 'uuid';
import { logSecurityEvent } from './securityLogger';

type EventDoc = {
  _id: { toString(): string };
  eventType: string;
  sourceIp: string;
  userId?: string | null;
  tenantId?: string | null;
  endpoint?: string;
  timestamp: Date;
  metadata?: Record<string, any>;
};

interface RuleMatch {
  key: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  sourceIp: string;
  users: string[];
  assets: string[];
  events: EventDoc[];
  findings: string[];
  attackPath: string[];
  confidence: number;
  recommendedActions: string[];
  mitreTactic: string;
  mitreTechnique: string;
}

interface DetectionRule {
  id: string;
  evaluate: (events: EventDoc[]) => RuleMatch[];
}

const FIVE_MINUTES = 5 * 60 * 1000;
const DEDUP_WINDOW = 10 * 60 * 1000;
const ADMIN_ROLES = ['TENANT_ADMIN', 'SUPER_ADMIN', 'ADMIN'];
const LOW_ROLES = ['STAFF', 'USER'];

function groupBy<T>(items: T[], keyFn: (item: T) => string | null | undefined): Map<string, T[]> {
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

function groupByUserIp(items: EventDoc[]): Map<string, EventDoc[]> {
  return groupBy(items, e => (e.userId ? `${e.userId}|${e.sourceIp}` : null));
}

function dominantIp(events: EventDoc[]): string {
  const counts = new Map<string, number>();
  for (const e of events) counts.set(e.sourceIp, (counts.get(e.sourceIp) ?? 0) + 1);
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1])[0]?.[0] ?? 'unknown';
}

function uniqueUsers(events: EventDoc[]): string[] {
  return Array.from(new Set(events.map(e => e.userId).filter((u): u is string => Boolean(u))));
}

export const detectionRules: DetectionRule[] = [
  {
    id: 'RULE-001',
    evaluate: (events) => {
      const failures = events.filter(e => e.eventType === 'AUTH_FAILURE');
      const matches: RuleMatch[] = [];
      for (const [ip, group] of groupBy(failures, e => e.sourceIp)) {
        if (group.length <= 10) continue;
        matches.push({
          key: ip,
          title: 'Brute Force Attack Detected',
          severity: 'high',
          sourceIp: ip,
          users: uniqueUsers(group),
          assets: ['/api/auth/login'],
          events: group,
          findings: ['VULN-009'],
          attackPath: ['Credential Compromise', 'Brute Force Login', 'Successful Authentication', 'Sensitive API Access'],
          confidence: 0.85,
          recommendedActions: ['Block source IP', 'Force password reset for affected user', 'Enable MFA'],
          mitreTactic: 'Credential Access',
          mitreTechnique: 'T1110 Brute Force',
        });
      }
      return matches;
    },
  },
  {
    id: 'RULE-002',
    evaluate: (events) => {
      const matches: RuleMatch[] = [];
      for (const [ip, group] of groupBy(events, e => e.sourceIp)) {
        const failures = group.filter(e => e.eventType === 'AUTH_FAILURE');
        if (failures.length <= 5) continue;
        const lastFailure = Math.max(...failures.map(f => new Date(f.timestamp).getTime()));
        const successes = group.filter(e => e.eventType === 'AUTH_SUCCESS' && new Date(e.timestamp).getTime() >= lastFailure);
        if (successes.length === 0) continue;
        const evidence = [...failures, ...successes];
        matches.push({
          key: ip,
          title: 'Possible Account Takeover',
          severity: 'critical',
          sourceIp: ip,
          users: uniqueUsers(successes),
          assets: ['/api/auth/login'],
          events: evidence,
          findings: ['VULN-009'],
          attackPath: ['Multiple Failed Logins', 'Successful Login', 'Session Created', 'Sensitive API Access'],
          confidence: 0.92,
          recommendedActions: ['Revoke session', 'Force password reset', 'Notify user', 'Enable MFA'],
          mitreTactic: 'Initial Access',
          mitreTechnique: 'T1078 Valid Accounts',
        });
      }
      return matches;
    },
  },
  {
    id: 'RULE-003',
    evaluate: (events) => {
      const access = events.filter(e => e.eventType === 'DATA_ACCESS' && e.userId && e.metadata?.resourceType === 'user');
      const matches: RuleMatch[] = [];
      for (const [, group] of groupByUserIp(access)) {
      const userId = group[0].userId as string;
        const resourceIds = new Set(group.map(e => e.metadata?.resourceId).filter(Boolean));
        if (resourceIds.size <= 10) continue;
        matches.push({
          key: userId,
          title: 'Possible IDOR Attack',
          severity: 'high',
          sourceIp: dominantIp(group),
          users: [userId],
          assets: ['/api/users/:userId'],
          events: group,
          findings: ['VULN-001'],
          attackPath: ['User Authentication', 'Access Own Resource', 'Change Resource ID', 'Access Another User Data'],
          confidence: 0.8,
          recommendedActions: ['Audit user access logs', 'Implement object-level authorization', 'Review data access patterns'],
          mitreTactic: 'Collection',
          mitreTechnique: 'T1083 File and Directory Discovery',
        });
      }
      return matches;
    },
  },
  {
    id: 'RULE-004',
    evaluate: (events) => {
      const crossTenant = events.filter(e => e.eventType === 'CROSS_TENANT_ACCESS_ATTEMPT');
      const matches: RuleMatch[] = [];
      for (const [, group] of groupByUserIp(crossTenant)) {
      const userId = group[0].userId as string;
        matches.push({
          key: userId,
          title: 'Cross-Tenant Data Access Attempt',
          severity: 'critical',
          sourceIp: dominantIp(group),
          users: [userId],
          assets: [group[0].endpoint || '/api/orders/:orderId'],
          events: group,
          findings: ['VULN-002'],
          attackPath: ['Tenant Alpha User', 'Authenticated Access', 'IDOR via Order ID', 'Tenant Beta Data Access'],
          confidence: 0.92,
          recommendedActions: ['Revoke session', 'Audit cross-tenant access logs', 'Patch order authorization'],
          mitreTactic: 'Collection',
          mitreTechnique: 'T1530 Data from Cloud Storage',
        });
      }
      return matches;
    },
  },
  {
    id: 'RULE-005',
    evaluate: (events) => {
      const escalations = events.filter(e =>
        e.eventType === 'PRIVILEGE_CHANGE' &&
        LOW_ROLES.includes(e.metadata?.oldRole) &&
        ADMIN_ROLES.includes(e.metadata?.newRole) &&
        LOW_ROLES.includes(e.metadata?.actorRole ?? e.metadata?.oldRole)
      );
      const matches: RuleMatch[] = [];
      for (const [, group] of groupByUserIp(escalations)) {
      const userId = group[0].userId as string;
        matches.push({
          key: userId,
          title: 'Privilege Escalation via Mass Assignment',
          severity: 'critical',
          sourceIp: dominantIp(group),
          users: [userId],
          assets: ['/api/users/:id', '/api/admin/users'],
          events: group,
          findings: ['VULN-011'],
          attackPath: ['STAFF User', 'Profile Update', 'Mass Assignment of role field', 'TENANT_ADMIN Access', 'Admin API Calls'],
          confidence: 0.88,
          recommendedActions: ['Revert user role', 'Audit admin actions taken', 'Patch mass assignment vulnerability'],
          mitreTactic: 'Privilege Escalation',
          mitreTechnique: 'T1078.004 Cloud Accounts',
        });
      }
      return matches;
    },
  },
  {
    id: 'RULE-006',
    evaluate: (events) => {
      const bulk = events.filter(e => e.eventType === 'BULK_DATA_ACCESS');
      const matches: RuleMatch[] = [];
      for (const [, group] of groupByUserIp(bulk)) {
      const userId = group[0].userId as string;
        if (group.length < 1) continue;
        const records = group.reduce((sum, e) => sum + (Number(e.metadata?.recordCount) || 0), 0);
        if (records < 100 && group.length < 3) continue;
        matches.push({
          key: userId,
          title: 'Possible Data Exfiltration',
          severity: 'critical',
          sourceIp: dominantIp(group),
          users: [userId],
          assets: ['/api/orders', '/api/orders/export'],
          events: group,
          findings: ['VULN-001', 'VULN-002'],
          attackPath: ['User Authentication', 'Bulk Data Access', 'Export Operation', 'Large Local Response'],
          confidence: 0.85,
          recommendedActions: ['Revoke session', 'Audit data access', 'Review export logs', 'Implement rate limiting on data access'],
          mitreTactic: 'Exfiltration',
          mitreTechnique: 'T1041 Exfiltration Over C2 Channel',
        });
      }
      return matches;
    },
  },
  {
    id: 'RULE-007',
    evaluate: (events) => {
      const adminChanges = events.filter(e =>
        (e.eventType === 'PRIVILEGE_CHANGE' || e.eventType === 'ADMIN_ACTION') &&
        e.metadata?.vulnerability !== 'VULN-011'
      );
      const matches: RuleMatch[] = [];
      for (const [, group] of groupByUserIp(adminChanges)) {
      const userId = group[0].userId as string;
        if (group.length <= 10) continue;
        matches.push({
          key: userId,
          title: 'Suspicious Admin Activity',
          severity: 'high',
          sourceIp: dominantIp(group),
          users: [userId],
          assets: ['/api/admin/users'],
          events: group,
          findings: ['VULN-003'],
          attackPath: ['Admin Authentication', 'Bulk Privilege Changes', 'Persistence via Role Grants'],
          confidence: 0.78,
          recommendedActions: ['Review admin audit trail', 'Verify admin identity', 'Revert unexpected role changes'],
          mitreTactic: 'Persistence',
          mitreTechnique: 'T1098 Account Manipulation',
        });
      }
      return matches;
    },
  },
  {
    id: 'RULE-008',
    evaluate: (events) => {
      const oneMinuteAgo = Date.now() - 60 * 1000;
      const requests = events.filter(e => e.eventType === 'API_REQUEST' && new Date(e.timestamp).getTime() >= oneMinuteAgo);
      const matches: RuleMatch[] = [];
      for (const [, group] of groupByUserIp(requests)) {
      const userId = group[0].userId as string;
        if (group.length <= 60) continue;
        matches.push({
          key: userId,
          title: 'API Abuse - Excessive Request Rate',
          severity: 'medium',
          sourceIp: dominantIp(group),
          users: [userId],
          assets: ['/api/orders'],
          events: group,
          findings: ['VULN-009'],
          attackPath: ['Authenticated User', 'Automated API Enumeration', 'Resource Exhaustion'],
          confidence: 0.7,
          recommendedActions: ['Apply per-user rate limiting', 'Review client behavior', 'Throttle source IP'],
          mitreTactic: 'Impact',
          mitreTechnique: 'T1499 Endpoint Denial of Service',
        });
      }
      return matches;
    },
  },
  {
    id: 'RULE-009',
    evaluate: (events) => {
      const abuse = events.filter(e => e.eventType === 'PAYMENT_UPDATED' && e.metadata?.note === 'business_logic_abuse');
      const matches: RuleMatch[] = [];
      for (const [, group] of groupByUserIp(abuse)) {
      const userId = group[0].userId as string;
        matches.push({
          key: userId,
          title: 'Payment Business Logic Abuse',
          severity: 'high',
          sourceIp: dominantIp(group),
          users: [userId],
          assets: ['/api/payments'],
          events: group,
          findings: ['VULN-012'],
          attackPath: ['Authenticated User', 'Order Created', 'Payment State Manipulated', 'Order Marked Paid'],
          confidence: 0.86,
          recommendedActions: ['Enforce payment state machine', 'Verify payment with gateway', 'Review affected orders'],
          mitreTactic: 'Impact',
          mitreTechnique: 'T1565 Data Manipulation',
        });
      }
      return matches;
    },
  },
];

async function recordAttackGraph(match: RuleMatch): Promise<void> {
  const graph = (await AttackGraph.findOne({ 'nodes.id': `ip-${match.sourceIp}` })) ?? (await AttackGraph.findOne({}));
  if (!graph) return;
  const ipNodeId = `ip-${match.sourceIp}`;
  const userNodeId = `user-${match.users[0] ?? 'unknown'}`;
  const vulnNodeId = `vuln-${match.findings[0] ?? 'unknown'}`;
  const hasNode = (id: string) => graph.nodes.some(n => n.id === id);
  if (!hasNode(ipNodeId)) graph.nodes.push({ id: ipNodeId, type: 'IP', label: match.sourceIp });
  if (!hasNode(userNodeId)) graph.nodes.push({ id: userNodeId, type: 'USER', label: match.users[0] ?? 'unknown' });
  if (!hasNode(vulnNodeId)) graph.nodes.push({ id: vulnNodeId, type: 'VULNERABILITY', label: match.findings[0] ?? 'unknown' });
  const hasEdge = (from: string, to: string, type: string) => graph.edges.some(e => e.from === from && e.to === to && e.type === type);
  if (!hasEdge(ipNodeId, userNodeId, 'AUTHENTICATED')) graph.edges.push({ from: ipNodeId, to: userNodeId, type: 'AUTHENTICATED' });
  if (!hasEdge(userNodeId, vulnNodeId, 'EXPLOITED')) graph.edges.push({ from: userNodeId, to: vulnNodeId, type: 'EXPLOITED' });
  await graph.save();
}

async function createIncident(match: RuleMatch, ruleId: string): Promise<boolean> {
  const since = new Date(Date.now() - DEDUP_WINDOW);
  const existing = await Incident.findOne({
    title: match.title,
    sourceIp: match.sourceIp,
    status: { $in: ['OPEN', 'INVESTIGATING'] },
    detectedAt: { $gte: since },
  });
  if (existing) return false;

  await Incident.create({
    id: `INC-${uuidv4().slice(0, 8)}`,
    title: match.title,
    severity: match.severity,
    status: 'OPEN',
    detectedAt: new Date(),
    sourceIp: match.sourceIp,
    users: match.users,
    assets: match.assets,
    eventIds: match.events.map(e => e._id.toString()).slice(0, 25),
    findings: match.findings,
    attackPath: match.attackPath,
    confidence: match.confidence,
    recommendedActions: match.recommendedActions,
    mitreTactic: match.mitreTactic,
    mitreTechnique: match.mitreTechnique,
  });

  await logSecurityEvent({
    eventType: 'SECURITY_FINDING_TRIGGERED',
    severity: match.severity,
    userId: match.users[0] ?? null,
    tenantId: null,
    sourceIp: match.sourceIp,
    endpoint: 'SOC_RULES_ENGINE',
    method: 'INTERNAL',
    metadata: { ruleId, incidentTitle: match.title },
  });

  await recordAttackGraph(match);
  return true;
}

export interface DetectionResult {
  ruleId: string;
  title: string;
  sourceIp: string;
  created: boolean;
}

export async function runDetectionRules(): Promise<DetectionResult[]> {
  const since = new Date(Date.now() - FIVE_MINUTES);
  const events = (await SecurityEvent.find({ timestamp: { $gte: since } }).lean()) as unknown as EventDoc[];
  const results: DetectionResult[] = [];

  for (const rule of detectionRules) {
    try {
      for (const match of rule.evaluate(events)) {
        const created = await createIncident(match, rule.id);
        results.push({ ruleId: rule.id, title: match.title, sourceIp: match.sourceIp, created });
      }
    } catch (err) {
      console.error(`[SOC] Rule ${rule.id} error:`, err);
    }
  }
  return results;
}

export async function startDetectionEngine(): Promise<void> {
  setInterval(() => {
    runDetectionRules().catch(err => console.error('[SOC] Detection run failed:', err));
  }, 30_000);
  console.log('[SOC] Detection rules engine started (30s interval)');
}
