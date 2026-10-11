import { AuditLog } from '../db/models';
import { newId } from './util';

export async function audit(
  actor: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  details: Record<string, unknown> = {},
  ip: string | null = null,
): Promise<void> {
  await AuditLog.create({ _id: newId('aud'), actor, action, targetType, targetId, details, ip });
}
