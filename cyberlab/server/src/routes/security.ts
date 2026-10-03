import { Router, Request, Response } from 'express';
import { Vulnerability } from '../models/Vulnerability';
import { SecurityEvent } from '../models/SecurityEvent';
import { AuditLog } from '../models/AuditLog';
import { Incident } from '../models/Incident';
import { Tenant } from '../models/Tenant';
import { User } from '../models/User';
import { AttackGraph } from '../models/AttackGraph';
import { runDetectionRules } from '../services/detectionEngine';
import { SCENARIOS, runScenario } from '../services/simulator';

const router = Router();

const INCIDENT_STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];

const DETECTION_RULES = [
  { id: 'RULE-001', name: 'Brute Force Detection', description: '>10 failed logins from the same IP within 5 minutes', condition: 'count(AUTH_FAILURE, same sourceIp, 5min) > 10', incidentType: 'BRUTE_FORCE', severity: 'high', enabled: true },
  { id: 'RULE-002', name: 'Account Takeover Detection', description: 'Successful login after many failed attempts', condition: 'AUTH_SUCCESS after count(AUTH_FAILURE, same sourceIp, 5min) > 5', incidentType: 'POSSIBLE_ACCOUNT_TAKEOVER', severity: 'critical', enabled: true },
  { id: 'RULE-003', name: 'IDOR Detection', description: 'Same user accesses many resource IDs rapidly', condition: 'count(distinct resourceId, same userId, 5min) > 10', incidentType: 'POSSIBLE_IDOR', severity: 'high', enabled: true },
  { id: 'RULE-004', name: 'Cross-Tenant Access Detection', description: 'User accesses a resource belonging to another tenant', condition: 'CROSS_TENANT_ACCESS_ATTEMPT event', incidentType: 'CROSS_TENANT_ATTACK', severity: 'critical', enabled: true },
  { id: 'RULE-005', name: 'Privilege Escalation Detection', description: 'STAFF/USER account changes a role to an admin role', condition: 'PRIVILEGE_CHANGE where oldRole in (STAFF,USER) and newRole in (TENANT_ADMIN,SUPER_ADMIN)', incidentType: 'PRIVILEGE_ESCALATION', severity: 'critical', enabled: true },
  { id: 'RULE-006', name: 'Data Exfiltration Detection', description: 'Large number of records accessed in a short period', condition: 'BULK_DATA_ACCESS recordCount >= 100 or >= 3 events per user in 5min', incidentType: 'POSSIBLE_DATA_EXFILTRATION', severity: 'critical', enabled: true },
  { id: 'RULE-007', name: 'Suspicious Admin Activity', description: 'Burst of privilege changes by one admin', condition: 'count(PRIVILEGE_CHANGE|ADMIN_ACTION, same userId, 5min) > 10', incidentType: 'SUSPICIOUS_ADMIN_ACTIVITY', severity: 'high', enabled: true },
  { id: 'RULE-008', name: 'API Abuse Detection', description: 'Excessive API request rate for one user', condition: 'count(API_REQUEST, same userId, 1min) > 60', incidentType: 'API_ABUSE', severity: 'medium', enabled: true },
  { id: 'RULE-009', name: 'Payment Business Logic Abuse', description: 'Payment accepted with tampered client-supplied fields', condition: 'PAYMENT_UPDATED with note=business_logic_abuse', incidentType: 'BUSINESS_LOGIC_ABUSE', severity: 'high', enabled: true },
];

// GET /api/security/demo-status
router.get('/demo-status', async (_req: Request, res: Response) => {
  const [vulnerabilityCount, tenantCount, userCount, securityEventCount, incidentCount] = await Promise.all([
    Vulnerability.countDocuments(),
    Tenant.countDocuments(),
    User.countDocuments(),
    SecurityEvent.countDocuments(),
    Incident.countDocuments(),
  ]);
  res.json({
    vulnerabilityCount,
    tenantCount,
    userCount,
    securityEventCount,
    attackScenarioCount: SCENARIOS.length,
    incidentCount,
    status: 'operational',
  });
});

// GET /api/security/findings
router.get('/findings', async (_req: Request, res: Response) => {
  const findings = await Vulnerability.find({}).sort({ id: 1 });
  res.json(findings.map(f => f.toObject({ versionKey: false, transform: (_d, ret) => { delete ret._id; return ret; } })));
});

// GET /api/security/findings/:id
router.get('/findings/:id', async (req: Request, res: Response) => {
  const finding = await Vulnerability.findOne({ id: req.params.id });
  if (!finding) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }
  res.json(finding.toObject({ versionKey: false, transform: (_d, ret) => { delete ret._id; return ret; } }));
});

// GET /api/security/events?limit=&eventType=&severity=&userId=&sourceIp=
router.get('/events', async (req: Request, res: Response) => {
  const limit = Math.min(parseInt(req.query.limit as string, 10) || 100, 500);
  const filter: Record<string, string> = {};
  for (const key of ['eventType', 'severity', 'userId', 'tenantId', 'sourceIp']) {
    const value = req.query[key];
    if (typeof value === 'string' && value) filter[key] = value;
  }
  const events = await SecurityEvent.find(filter).sort({ timestamp: -1 }).limit(limit);
  res.json(events.map(e => e.toJSON()));
});

// GET /api/security/incidents
router.get('/incidents', async (_req: Request, res: Response) => {
  const incidents = await Incident.find({}).sort({ detectedAt: -1 }).limit(200);
  res.json(incidents.map(i => i.toObject({ versionKey: false, transform: (_d, ret) => { delete ret._id; return ret; } })));
});

// PATCH /api/security/incidents/:id  { status }
router.patch('/incidents/:id', async (req: Request, res: Response) => {
  const { status } = req.body;
  if (!INCIDENT_STATUSES.includes(status)) {
    res.status(400).json({ error: `status must be one of ${INCIDENT_STATUSES.join(', ')}` });
    return;
  }
  const incident = await Incident.findOneAndUpdate({ id: req.params.id }, { $set: { status } }, { new: true });
  if (!incident) {
    res.status(404).json({ error: 'Incident not found' });
    return;
  }
  res.json(incident.toObject({ versionKey: false, transform: (_d, ret) => { delete ret._id; return ret; } }));
});

// GET /api/security/audit-logs
router.get('/audit-logs', async (req: Request, res: Response) => {
  const limit = Math.min(parseInt(req.query.limit as string, 10) || 100, 500);
  const logs = await AuditLog.find({}).sort({ timestamp: -1 }).limit(limit);
  res.json(logs.map(l => ({ ...l.toObject({ versionKey: false }), id: String(l._id) })));
});

// GET /api/security/attack-graph
router.get('/attack-graph', async (_req: Request, res: Response) => {
  const graph = await AttackGraph.findOne({});
  if (!graph) {
    res.json({ nodes: [], edges: [], attackPath: [] });
    return;
  }
  res.json({
    nodes: graph.nodes.map(n => ({ id: n.id, type: n.type, label: n.label, metadata: n.metadata })),
    edges: graph.edges.map(e => ({ from: e.from, to: e.to, type: e.type })),
    attackPath: graph.attackPath ?? [],
  });
});

// GET /api/security/detection-rules
router.get('/detection-rules', (_req: Request, res: Response) => {
  res.json(DETECTION_RULES);
});

// GET /api/security/scenarios
router.get('/scenarios', (_req: Request, res: Response) => {
  res.json(SCENARIOS);
});

// POST /api/security/run-detection
router.post('/run-detection', async (_req: Request, res: Response) => {
  const results = await runDetectionRules();
  res.json({ success: true, message: 'Detection rules executed', results });
});

// POST /api/security/simulate/:scenarioId  - runs a controlled attack against this API only (loopback)
router.post('/simulate/:scenarioId', async (req: Request, res: Response) => {
  try {
    const result = await runScenario(req.params.scenarioId);
    res.json(result);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Simulation failed';
    res.status(message.startsWith('Unknown scenario') ? 404 : 500).json({ error: message });
  }
});

export default router;
