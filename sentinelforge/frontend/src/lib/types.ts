export interface User {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'analyst' | 'viewer';
}

export interface Application {
  id: string;
  name: string;
  baseUrl: string;
  adapter: string;
  status: string;
  discovered: { endpointCount?: number };
  createdAt: string;
  config?: { openapiUrl?: string; authHeaderName?: string; authHeaderValue?: string };
  scanIntervalMinutes?: number;
}

export interface Finding {
  id: string;
  applicationId: string;
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
  detectedAt: string;
  updatedAt: string;
  aiAnalysis?: Record<string, unknown>;
  relatedIncidents?: Incident[];
}

export interface Incident {
  id: string;
  applicationId?: string;
  title: string;
  rule: string;
  subject: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: string;
  detectedAt: string;
  updatedAt: string;
  sourceIp?: string;
  users: string[];
  assets: string[];
  confidence: number;
  mitre?: string;
  recommendedActions: string[];
  investigation?: Record<string, unknown>;
  assignedTo?: string;
  assignedToName?: string;
  postmortemUrl?: string;
}

export interface OrgUser {
  id: string;
  name: string;
  email: string;
  role: string;
}

export interface IncidentComment {
  id: string;
  incidentId: string;
  authorId: string;
  authorName: string;
  text: string;
  createdAt: string;
}

export interface IncidentDetail extends Incident {
  events: SecurityEvent[];
  correlations: { id: string; reason: string; confidence: number }[];
  findings: Finding[];
}

export interface SecurityEvent {
  id: string;
  timestamp: string;
  eventType: string;
  severity: string;
  userId?: string;
  endpoint?: string;
  sourceIp?: string;
  metadata: Record<string, unknown>;
}

export interface AttackGraph {
  summary: string;
  nodes: { id: string; type: string; label: string; metadata: Record<string, unknown> }[];
  edges: { id: string; source: string; target: string; type: string; label?: string }[];
}

export interface Scenario {
  id: string;
  name: string;
}

export interface RiskScore {
  score: number;
  breakdown: { severity: number; epss: number; kev: number; exposure: number };
  exposure: 'public' | 'authenticated';
}

export interface RankedFinding {
  id: string;
  vulnKey: string;
  title: string;
  severity: string;
  applicationId: string;
  applicationName: string;
  risk: RiskScore;
}

export interface OwaspCategoryCoverage {
  code: string;
  label: string;
  family: 'api-top-10' | 'web-top-10';
  openFindings: number;
  totalFindings: number;
}

export interface ComplianceCoverage {
  apiTop10: { tested: number; total: number; categories: OwaspCategoryCoverage[] };
  webTop10: { tested: number; total: number; categories: OwaspCategoryCoverage[] };
}

export interface PostureMetrics {
  scanHistory: { startedAt: string; findingsOpen: number; checksTotal: number }[];
  avgTimeToFixHours: number | null;
  findingsVerified: number;
  severityCounts: Record<string, number>;
}

export interface ScanRunDiff {
  new: string[];
  resolved: string[];
  recurring: string[];
  regressed: string[];
}

export interface IpReputation {
  available: boolean;
  reason?: string;
  ip?: string;
  isPublic?: boolean;
  abuseConfidenceScore?: number;
  totalReports?: number;
  countryCode?: string;
  isp?: string;
  lastReportedAt?: string;
}

export interface TestConnectionResult {
  ok: boolean;
  detail?: string;
  endpointPreviewCount?: number;
}
