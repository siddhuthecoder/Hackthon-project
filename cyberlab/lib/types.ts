export type Role = 'SUPER_ADMIN' | 'TENANT_ADMIN' | 'MANAGER' | 'STAFF' | 'USER';

export type TenantId = string;

export interface Tenant {
  id: TenantId;
  name: string;
  plan: 'free' | 'pro' | 'enterprise';
  createdAt: string;
  userCount: number;
  productCount: number;
  orderCount: number;
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  tenantId: TenantId;
  active: boolean;
  lastLogin: string | null;
  createdAt: string;
  phone?: string;
  avatar?: string;
}

export interface Product {
  id: string;
  name: string;
  description: string;
  price: number;
  category: string;
  tenantId: TenantId;
  stock: number;
  createdAt: string;
}

export interface Order {
  id: string;
  orderNumber: string;
  customerId: string;
  customerName: string;
  tenantId: TenantId;
  items: { productId: string; name: string; quantity: number; price: number }[];
  total: number;
  status: 'pending' | 'paid' | 'shipped' | 'delivered' | 'cancelled' | 'refunded';
  createdAt: string;
}

export interface Payment {
  id: string;
  orderId: string;
  amount: number;
  status: 'pending' | 'completed' | 'failed' | 'refunded';
  method: 'card' | 'bank' | 'wallet';
  createdAt: string;
}

export type SecurityEventType =
  | 'AUTH_SUCCESS'
  | 'AUTH_FAILURE'
  | 'PASSWORD_RESET'
  | 'SESSION_CREATED'
  | 'SESSION_REVOKED'
  | 'API_REQUEST'
  | 'API_ERROR'
  | 'AUTHORIZATION_FAILURE'
  | 'PRIVILEGE_CHANGE'
  | 'ADMIN_ACTION'
  | 'DATA_ACCESS'
  | 'BULK_DATA_ACCESS'
  | 'CROSS_TENANT_ACCESS_ATTEMPT'
  | 'FILE_UPLOAD'
  | 'FILE_DOWNLOAD'
  | 'SUSPICIOUS_REQUEST'
  | 'RATE_LIMIT_TRIGGERED'
  | 'PAYMENT_CREATED'
  | 'PAYMENT_UPDATED'
  | 'REFUND_CREATED'
  | 'SECURITY_FINDING_TRIGGERED';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  eventType: SecurityEventType;
  severity: Severity;
  userId: string | null;
  tenantId: TenantId | null;
  sourceIp: string;
  endpoint: string;
  method: string;
  userAgent: string;
  requestId: string;
  mitreTechnique?: string | null;
  metadata: Record<string, unknown>;
}

export interface AuditLog {
  id: string;
  actor: string;
  actorName: string;
  action: string;
  target: string | null;
  targetName: string | null;
  tenantId: TenantId;
  oldValue: string | null;
  newValue: string | null;
  timestamp: string;
  details: string | null;
}

export interface Vulnerability {
  id: string;
  type: string;
  title: string;
  description: string;
  severity: Severity;
  endpoint: string;
  method: string;
  status: 'OPEN' | 'REMEDIATED' | 'VERIFIED';
  cwe: string;
  owasp: string;
  mitreTactic: string | null;
  mitreTechnique: string | null;
  attackScenario: string;
  secureEndpoint: string;
  vulnerableEndpoint: string;
}

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  detectedAt: string;
  sourceIp: string;
  users: string[];
  assets: string[];
  eventIds: string[];
  findings: string[];
  attackPath: string[];
  confidence: number;
  recommendedActions: string[];
  mitreTactic: string | null;
  mitreTechnique: string | null;
}

export interface AttackGraphNode {
  id: string;
  type: 'USER' | 'IP' | 'DEVICE' | 'API' | 'ENDPOINT' | 'VULNERABILITY' | 'ASSET' | 'DATABASE' | 'TENANT';
  label: string;
  metadata?: Record<string, string>;
}

export interface AttackGraphEdge {
  from: string;
  to: string;
  type: 'ACCESSED' | 'AUTHENTICATED' | 'EXPLOITED' | 'TARGETED' | 'BELONGS_TO' | 'ESCALATED_TO' | 'ACCESSES';
}

export interface AttackGraph {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  attackPath?: string[];
}

export interface AttackScenario {
  id: string;
  name: string;
  description: string;
  mitreTactic: string;
  mitreTechnique: string;
  steps: { step: number; action: string; expectedResult: string }[];
  detectionRule: string;
  incidentType: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  condition: string;
  incidentType: string;
  severity: Severity;
  enabled: boolean;
}

export interface LabStats {
  vulnerabilityCount: number;
  tenantCount: number;
  userCount: number;
  securityEventCount: number;
  attackScenarioCount: number;
  incidentCount: number;
}

export interface Customer {
  id: string;
  name: string;
  email: string;
  company: string;
  phone: string;
  tenantId: TenantId;
  createdAt: string;
}

export interface Comment {
  id: string;
  productId: string;
  userId: string;
  userName: string;
  tenantId: TenantId;
  content: string;
  sanitized: boolean;
  createdAt: string;
}

export interface Notification {
  id: string;
  type: string;
  title: string;
  message: string;
  severity: Severity;
  tenantId: TenantId | null;
  incidentId: string | null;
  read: boolean;
  createdAt: string;
}

export interface ScenarioInfo {
  id: string;
  name: string;
  description: string;
  mitreTactic: string;
  mitreTechnique: string;
  detectionRule: string;
  incidentType: string;
  uiButton: boolean;
}

export interface SimulationStep {
  step: number;
  action: string;
  result: string;
  status: 'success' | 'failed';
}

export interface SimulationResult {
  scenarioId: string;
  name: string;
  sourceIp: string;
  startedAt: string;
  steps: SimulationStep[];
  eventsGenerated: number;
  detections: { ruleId: string; title: string; sourceIp: string; created: boolean }[];
  incidents: { id: string; title: string; severity: Severity; confidence: number; status: IncidentStatus }[];
}

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  role: Role;
  tenantId: TenantId;
}

export interface DemoStatus extends LabStats {
  status: string;
}
