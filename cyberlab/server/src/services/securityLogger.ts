import { v4 as uuidv4 } from 'uuid';
import { SecurityEvent, ISecurityEvent, SecurityEventType, Severity } from '../models/SecurityEvent';
import { publishEvent } from './redis';

export interface SecurityEventInput {
  eventType: SecurityEventType;
  severity: Severity;
  userId?: string | null;
  tenantId?: string | null;
  sourceIp: string;
  endpoint: string;
  method: string;
  userAgent?: string;
  requestId?: string;
  mitreTechnique?: string | null;
  metadata?: Record<string, unknown>;
}

export async function logSecurityEvent(input: SecurityEventInput): Promise<ISecurityEvent> {
  const event = await SecurityEvent.create({
    timestamp: new Date(),
    eventType: input.eventType,
    severity: input.severity,
    userId: input.userId ?? null,
    tenantId: input.tenantId ?? null,
    sourceIp: input.sourceIp,
    endpoint: input.endpoint,
    method: input.method,
    userAgent: input.userAgent ?? 'unknown',
    requestId: input.requestId ?? uuidv4(),
    mitreTechnique: input.mitreTechnique ?? null,
    metadata: input.metadata ?? {},
  });

  const payload = event.toJSON();
  console.log(JSON.stringify({ stream: 'security', ...payload }));
  await publishEvent('security-events', payload);

  return event;
}

export async function logAudit(
  actor: string,
  actorName: string,
  action: string,
  tenantId: string,
  options?: {
    target?: string | null;
    targetName?: string | null;
    oldValue?: string | null;
    newValue?: string | null;
    details?: string | null;
  }
): Promise<void> {
  const { AuditLog } = await import('../models/AuditLog');
  await AuditLog.create({
    actor,
    actorName,
    action,
    target: options?.target ?? null,
    targetName: options?.targetName ?? null,
    tenantId,
    oldValue: options?.oldValue ?? null,
    newValue: options?.newValue ?? null,
    details: options?.details ?? null,
    timestamp: new Date(),
  });
}
