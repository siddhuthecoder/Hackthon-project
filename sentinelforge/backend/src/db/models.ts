import mongoose, { Document, Schema } from 'mongoose';

const { Mixed } = Schema.Types;

function toJson(schema: Schema): void {
  schema.set('toJSON', {
    transform: (_doc, ret: Record<string, unknown>) => {
      ret.id = String(ret._id);
      delete ret._id;
      delete ret.__v;
      return ret;
    },
  });
}

// --- organizations / users -------------------------------------------------

export interface IOrganization extends Document<string> {
  name: string;
  createdAt: Date;
}

const OrganizationSchema = new Schema<IOrganization>(
  { _id: String, name: { type: String, required: true } },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(OrganizationSchema);
export const Organization = mongoose.model<IOrganization>('Organization', OrganizationSchema, 'organizations');

export interface IUser extends Document<string> {
  organizationId: string;
  email: string;
  name: string;
  passwordHash: string;
  role: 'admin' | 'analyst' | 'viewer';
  active: boolean;
  createdAt: Date;
}

const UserSchema = new Schema<IUser>(
  {
    _id: String,
    organizationId: { type: String, required: true, index: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    name: { type: String, required: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['admin', 'analyst', 'viewer'], required: true },
    active: { type: Boolean, default: true },
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(UserSchema);
export const User = mongoose.model<IUser>('User', UserSchema, 'users');

// --- applications / assets / endpoints -------------------------------------

export interface IApplication extends Document<string> {
  organizationId: string;
  name: string;
  environment: string;
  baseUrl: string;
  repository?: string;
  authType: string;
  adapter: string;
  discovered: Record<string, unknown>;
  status: string;
  createdAt: Date;
  discoveredAt?: Date;
  /** Adapter-specific settings for targets that don't ship their own adapter class — e.g. the
   * generic adapter's openapiUrl/authHeaderName/authHeaderValue. See modules/targets/generic. */
  config: Record<string, unknown>;
  /** Unset = manual-trigger only. Set = the scheduler (modules/scheduler/rescan.ts) re-scans this
   * application on this cadence and computes a new/resolved/recurring/regressed diff each time. */
  scanIntervalMinutes?: number;
}

const ApplicationSchema = new Schema<IApplication>(
  {
    _id: String,
    organizationId: { type: String, required: true, index: true },
    name: { type: String, required: true },
    environment: { type: String, default: 'local' },
    baseUrl: { type: String, required: true },
    repository: String,
    authType: { type: String, default: 'jwt' },
    adapter: { type: String, default: 'cyberlab' },
    discovered: { type: Mixed, default: {} },
    status: { type: String, default: 'REGISTERED' },
    discoveredAt: Date,
    config: { type: Mixed, default: {} },
    scanIntervalMinutes: Number,
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(ApplicationSchema);
export const Application = mongoose.model<IApplication>('Application', ApplicationSchema, 'applications');

export interface IAsset extends Document<string> {
  applicationId: string;
  kind: string;
  name: string;
  details: Record<string, unknown>;
  createdAt: Date;
}

const AssetSchema = new Schema<IAsset>(
  {
    _id: String,
    applicationId: { type: String, required: true, index: true },
    kind: { type: String, required: true },
    name: { type: String, required: true },
    details: { type: Mixed, default: {} },
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
AssetSchema.index({ applicationId: 1, kind: 1, name: 1 }, { unique: true });
toJson(AssetSchema);
export const Asset = mongoose.model<IAsset>('Asset', AssetSchema, 'assets');

export interface IEndpoint extends Document<string> {
  applicationId: string;
  assetId?: string;
  method: string;
  path: string;
  authRequired: boolean;
  source: string;
  createdAt: Date;
}

const EndpointSchema = new Schema<IEndpoint>(
  {
    _id: String,
    applicationId: { type: String, required: true, index: true },
    assetId: String,
    method: { type: String, required: true },
    path: { type: String, required: true },
    authRequired: { type: Boolean, default: true },
    source: { type: String, default: 'discovery' },
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
EndpointSchema.index({ applicationId: 1, method: 1, path: 1 }, { unique: true });
toJson(EndpointSchema);
export const Endpoint = mongoose.model<IEndpoint>('Endpoint', EndpointSchema, 'endpoints');

// --- scanning / findings ----------------------------------------------------

export interface IScanRunDiff {
  new: string[];
  resolved: string[];
  recurring: string[];
  regressed: string[];
}

export interface IScanRun extends Document<string> {
  applicationId: string;
  status: string;
  startedAt: Date;
  finishedAt?: Date;
  checksTotal: number;
  findingsOpen: number;
  triggeredBy?: string;
  /** vulnKey diff against the application's previous completed scan run. Unset on an
   * application's first scan (nothing to diff against). See modules/scanner/diff.ts. */
  diff?: IScanRunDiff;
}

const ScanRunSchema = new Schema<IScanRun>(
  {
    _id: String,
    applicationId: { type: String, required: true, index: true },
    status: { type: String, required: true },
    startedAt: { type: Date, default: Date.now },
    finishedAt: Date,
    checksTotal: { type: Number, default: 0 },
    findingsOpen: { type: Number, default: 0 },
    triggeredBy: String,
    diff: {
      type: new Schema<IScanRunDiff>({
        new: { type: [String], default: [] },
        resolved: { type: [String], default: [] },
        recurring: { type: [String], default: [] },
        regressed: { type: [String], default: [] },
      }, { _id: false }),
      required: false,
    },
  },
  { timestamps: false },
);
toJson(ScanRunSchema);
export const ScanRun = mongoose.model<IScanRun>('ScanRun', ScanRunSchema, 'scan_runs');

export interface IScanResult extends Document<string> {
  scanRunId: string;
  vulnKey: string;
  outcome: string;
  request: Record<string, unknown>;
  response: Record<string, unknown>;
  summary: string;
  createdAt: Date;
}

const ScanResultSchema = new Schema<IScanResult>(
  {
    _id: String,
    scanRunId: { type: String, required: true, index: true },
    vulnKey: { type: String, required: true },
    outcome: { type: String, required: true },
    request: { type: Mixed, default: {} },
    response: { type: Mixed, default: {} },
    summary: { type: String, default: '' },
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(ScanResultSchema);
export const ScanResult = mongoose.model<IScanResult>('ScanResult', ScanResultSchema, 'scan_results');

export interface IVulnerability extends Document<string> {
  applicationId: string;
  assetId?: string;
  vulnKey: string;
  title: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  cwe?: string;
  owasp?: string;
  endpoint: string;
  method: string;
  evidence: Record<string, unknown>;
  description: string;
  impact: string;
  remediation: string;
  status: string;
  detectedAt: Date;
  updatedAt: Date;
  scanRunId?: string;
  aiAnalysis?: Record<string, unknown>;
}

const VulnerabilitySchema = new Schema<IVulnerability>(
  {
    _id: String,
    applicationId: { type: String, required: true, index: true },
    assetId: String,
    vulnKey: { type: String, required: true },
    title: { type: String, required: true },
    type: { type: String, required: true },
    severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], required: true, index: true },
    confidence: { type: Number, required: true },
    cwe: String,
    owasp: String,
    endpoint: { type: String, required: true },
    method: { type: String, required: true },
    evidence: { type: Mixed, default: {} },
    description: { type: String, required: true },
    impact: { type: String, required: true },
    remediation: { type: String, required: true },
    status: { type: String, default: 'OPEN', index: true },
    detectedAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    scanRunId: String,
    aiAnalysis: Mixed,
  },
  { timestamps: false },
);
VulnerabilitySchema.index({ applicationId: 1, vulnKey: 1 }, { unique: true });
toJson(VulnerabilitySchema);
export const Vulnerability = mongoose.model<IVulnerability>('Vulnerability', VulnerabilitySchema, 'vulnerabilities');

// --- live security events ---------------------------------------------------

export interface ISecurityEvent extends Document<string> {
  source: string;
  sourceId: string;
  applicationId?: string;
  timestamp: Date;
  eventType: string;
  severity: string;
  userId?: string;
  tenantId?: string;
  sourceIp?: string;
  endpoint?: string;
  method?: string;
  statusCode?: number;
  requestId?: string;
  userAgent?: string;
  metadata: Record<string, unknown>;
  ingestedAt: Date;
}

const SecurityEventSchema = new Schema<ISecurityEvent>(
  {
    _id: String,
    source: { type: String, required: true },
    sourceId: { type: String, required: true },
    applicationId: String,
    timestamp: { type: Date, required: true, index: true },
    eventType: { type: String, required: true, index: true },
    severity: { type: String, required: true },
    userId: { type: String, index: true },
    tenantId: { type: String, index: true },
    sourceIp: { type: String, index: true },
    endpoint: { type: String, index: true },
    method: String,
    statusCode: Number,
    requestId: String,
    userAgent: String,
    metadata: { type: Mixed, default: {} },
    ingestedAt: { type: Date, default: Date.now },
  },
  { timestamps: false },
);
SecurityEventSchema.index({ source: 1, sourceId: 1 }, { unique: true });
toJson(SecurityEventSchema);
export const SecurityEvent = mongoose.model<ISecurityEvent>('SecurityEvent', SecurityEventSchema, 'security_events');

// --- detections / incidents --------------------------------------------------

export interface IDetection extends Document<string> {
  rule: string;
  subject: string;
  severity: string;
  confidence: number;
  evidence: Record<string, unknown>;
  eventIds: string[];
  detectedAt: Date;
  incidentId?: string;
}

const DetectionSchema = new Schema<IDetection>(
  {
    _id: String,
    rule: { type: String, required: true },
    subject: { type: String, required: true },
    severity: { type: String, required: true },
    confidence: { type: Number, required: true },
    evidence: { type: Mixed, default: {} },
    eventIds: { type: [String], default: [] },
    detectedAt: { type: Date, default: Date.now },
    incidentId: String,
  },
  { timestamps: false },
);
DetectionSchema.index({ rule: 1, subject: 1 });
toJson(DetectionSchema);
export const Detection = mongoose.model<IDetection>('Detection', DetectionSchema, 'detections');

export interface IIncident extends Document<string> {
  applicationId?: string;
  title: string;
  rule: string;
  subject: string;
  severity: string;
  status: string;
  detectedAt: Date;
  updatedAt: Date;
  sourceIp?: string;
  users: string[];
  assets: string[];
  eventIds: string[];
  confidence: number;
  mitre?: string;
  recommendedActions: string[];
  investigation?: Record<string, unknown>;
  assignedTo?: string;
  assignedToName?: string;
  postmortemUrl?: string;
}

const IncidentSchema = new Schema<IIncident>(
  {
    _id: String,
    applicationId: String,
    title: { type: String, required: true },
    rule: { type: String, required: true },
    subject: { type: String, required: true },
    severity: { type: String, required: true, index: true },
    status: { type: String, default: 'OPEN', index: true },
    detectedAt: { type: Date, default: Date.now, index: true },
    updatedAt: { type: Date, default: Date.now },
    sourceIp: String,
    users: { type: [String], default: [] },
    assets: { type: [String], default: [] },
    eventIds: { type: [String], default: [] },
    confidence: { type: Number, required: true },
    mitre: String,
    recommendedActions: { type: [String], default: [] },
    investigation: Mixed,
    assignedTo: String,
    assignedToName: String,
    postmortemUrl: String,
  },
  { timestamps: false },
);
toJson(IncidentSchema);
export const Incident = mongoose.model<IIncident>('Incident', IncidentSchema, 'incidents');

export interface IIncidentComment extends Document<string> {
  incidentId: string;
  authorId: string;
  authorName: string;
  text: string;
  createdAt: Date;
}

const IncidentCommentSchema = new Schema<IIncidentComment>(
  {
    _id: String,
    incidentId: { type: String, required: true, index: true },
    authorId: { type: String, required: true },
    authorName: { type: String, required: true },
    text: { type: String, required: true },
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(IncidentCommentSchema);
export const IncidentComment = mongoose.model<IIncidentComment>('IncidentComment', IncidentCommentSchema, 'incident_comments');

export interface ICorrelation extends Document<string> {
  findingId: string;
  incidentId: string;
  evidence: Record<string, unknown>;
  confidence: number;
  reason: string;
  createdAt: Date;
}

const CorrelationSchema = new Schema<ICorrelation>(
  {
    _id: String,
    findingId: { type: String, required: true, index: true },
    incidentId: { type: String, required: true, index: true },
    evidence: { type: Mixed, required: true },
    confidence: { type: Number, required: true },
    reason: { type: String, required: true },
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
CorrelationSchema.index({ findingId: 1, incidentId: 1 }, { unique: true });
toJson(CorrelationSchema);
export const Correlation = mongoose.model<ICorrelation>('Correlation', CorrelationSchema, 'correlations');

// --- attack graph -------------------------------------------------------------

export interface IAttackNode {
  id: string;
  type: string;
  label: string;
  metadata: Record<string, unknown>;
}

export interface IAttackEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label?: string;
}

export interface IAttackPath extends Document<string> {
  incidentId: string;
  summary: string;
  nodes: IAttackNode[];
  edges: IAttackEdge[];
  createdAt: Date;
}

const AttackPathSchema = new Schema<IAttackPath>(
  {
    _id: String,
    incidentId: { type: String, required: true, unique: true },
    summary: { type: String, required: true },
    nodes: {
      type: [new Schema<IAttackNode>({ id: String, type: String, label: String, metadata: { type: Mixed, default: {} } }, { _id: false })],
      default: [],
    },
    edges: {
      type: [new Schema<IAttackEdge>({ id: String, source: String, target: String, type: String, label: String }, { _id: false })],
      default: [],
    },
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(AttackPathSchema);
export const AttackPath = mongoose.model<IAttackPath>('AttackPath', AttackPathSchema, 'attack_paths');

// --- threat intelligence -------------------------------------------------------

export interface IThreatIndicator extends Document<string> {
  kind: string;
  value: string;
  details: Record<string, unknown>;
}

const ThreatIndicatorSchema = new Schema<IThreatIndicator>(
  {
    _id: String,
    kind: { type: String, required: true },
    value: { type: String, required: true },
    details: { type: Mixed, default: {} },
  },
  { timestamps: false },
);
ThreatIndicatorSchema.index({ kind: 1, value: 1 }, { unique: true });
toJson(ThreatIndicatorSchema);
export const ThreatIndicator = mongoose.model<IThreatIndicator>('ThreatIndicator', ThreatIndicatorSchema, 'threat_indicators');

// --- remediation / verification / response -------------------------------------

export interface IRemediationTask extends Document<string> {
  findingId: string;
  status: string;
  plan: Record<string, unknown>;
  appliedAt?: Date;
  appliedBy?: string;
  createdAt: Date;
}

const RemediationTaskSchema = new Schema<IRemediationTask>(
  {
    _id: String,
    findingId: { type: String, required: true, index: true },
    status: { type: String, default: 'PROPOSED' },
    plan: { type: Mixed, required: true },
    appliedAt: Date,
    appliedBy: String,
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(RemediationTaskSchema);
export const RemediationTask = mongoose.model<IRemediationTask>('RemediationTask', RemediationTaskSchema, 'remediation_tasks');

export interface IVerificationRun extends Document<string> {
  findingId: string;
  remediationTaskId?: string;
  passed: boolean;
  outcome: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  createdBy?: string;
  createdAt: Date;
}

const VerificationRunSchema = new Schema<IVerificationRun>(
  {
    _id: String,
    findingId: { type: String, required: true, index: true },
    remediationTaskId: String,
    passed: { type: Boolean, required: true },
    outcome: { type: String, required: true },
    before: { type: Mixed, required: true },
    after: { type: Mixed, required: true },
    createdBy: String,
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(VerificationRunSchema);
export const VerificationRun = mongoose.model<IVerificationRun>('VerificationRun', VerificationRunSchema, 'verification_runs');

export interface IResponseAction extends Document<string> {
  incidentId: string;
  action: string;
  target?: string;
  status: string;
  highImpact: boolean;
  details: Record<string, unknown>;
  requestedBy?: string;
  approvedBy?: string;
  executedAt?: Date;
  createdAt: Date;
}

const ResponseActionSchema = new Schema<IResponseAction>(
  {
    _id: String,
    incidentId: { type: String, required: true, index: true },
    action: { type: String, required: true },
    target: String,
    status: { type: String, default: 'PENDING_APPROVAL' },
    highImpact: { type: Boolean, default: true },
    details: { type: Mixed, default: {} },
    requestedBy: String,
    approvedBy: String,
    executedAt: Date,
  },
  { timestamps: { createdAt: 'createdAt', updatedAt: false } },
);
toJson(ResponseActionSchema);
export const ResponseAction = mongoose.model<IResponseAction>('ResponseAction', ResponseActionSchema, 'response_actions');

// --- audit / agent runs / simulations --------------------------------------------

export interface IAuditLog extends Document<string> {
  timestamp: Date;
  actor?: string | null;
  action: string;
  targetType?: string | null;
  targetId?: string | null;
  details: Record<string, unknown>;
  ip?: string | null;
}

const AuditLogSchema = new Schema<IAuditLog>(
  {
    _id: String,
    timestamp: { type: Date, default: Date.now, index: true },
    actor: String,
    action: { type: String, required: true },
    targetType: String,
    targetId: String,
    details: { type: Mixed, default: {} },
    ip: String,
  },
  { timestamps: false },
);
toJson(AuditLogSchema);
export const AuditLog = mongoose.model<IAuditLog>('AuditLog', AuditLogSchema, 'audit_logs');

export interface IAgentRun extends Document<string> {
  agent: string;
  mode: string;
  subjectType?: string;
  subjectId?: string;
  status: string;
  startedAt: Date;
  finishedAt?: Date;
  toolCalls: unknown[];
  output?: Record<string, unknown>;
  error?: string;
}

const AgentRunSchema = new Schema<IAgentRun>(
  {
    _id: String,
    agent: { type: String, required: true },
    mode: { type: String, required: true },
    subjectType: String,
    subjectId: String,
    status: { type: String, required: true },
    startedAt: { type: Date, default: Date.now },
    finishedAt: Date,
    toolCalls: { type: Mixed, default: [] },
    output: Mixed,
    error: String,
  },
  { timestamps: false },
);
toJson(AgentRunSchema);
export const AgentRun = mongoose.model<IAgentRun>('AgentRun', AgentRunSchema, 'agent_runs');

export interface ISimulationRun extends Document<string> {
  scenarioId: string;
  name: string;
  sourceIp?: string;
  startedAt: Date;
  result: Record<string, unknown>;
  triggeredBy?: string;
}

const SimulationRunSchema = new Schema<ISimulationRun>(
  {
    _id: String,
    scenarioId: { type: String, required: true },
    name: { type: String, required: true },
    sourceIp: String,
    startedAt: { type: Date, default: Date.now },
    result: { type: Mixed, default: {} },
    triggeredBy: String,
  },
  { timestamps: false },
);
toJson(SimulationRunSchema);
export const SimulationRun = mongoose.model<ISimulationRun>('SimulationRun', SimulationRunSchema, 'simulation_runs');
