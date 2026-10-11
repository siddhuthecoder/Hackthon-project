import { SecurityEvent } from '../../db/models';
import { publish } from '../../lib/bus';
import { newId } from '../../lib/util';
import { CyberLabAdapter } from '../cyberlab/adapter';

interface RawCyberLabEvent {
  id: string;
  timestamp: string;
  eventType: string;
  severity: string;
  userId?: string | null;
  tenantId?: string | null;
  sourceIp?: string;
  endpoint?: string;
  method?: string;
  userAgent?: string;
  requestId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Pulls recent events from CyberLab and stores any not already ingested (deduped on
 * source+sourceId, so re-polling overlapping windows is safe). Returns the newly ingested events
 * so callers (detection) can react without re-querying.
 */
export async function ingestEvents(applicationId: string, lab: CyberLabAdapter): Promise<number> {
  const raw = (await lab.getEvents()) as RawCyberLabEvent[];
  let ingested = 0;

  for (const event of raw) {
    if (!event.id) continue;
    const exists = await SecurityEvent.findOne({ source: 'cyberlab', sourceId: event.id }).select('_id');
    if (exists) continue;

    const doc = await SecurityEvent.create({
      _id: newId('ev'),
      source: 'cyberlab',
      sourceId: event.id,
      applicationId,
      timestamp: new Date(event.timestamp),
      eventType: event.eventType,
      severity: event.severity,
      userId: event.userId ?? undefined,
      tenantId: event.tenantId ?? undefined,
      sourceIp: event.sourceIp,
      endpoint: event.endpoint,
      method: event.method,
      requestId: event.requestId,
      userAgent: event.userAgent,
      metadata: event.metadata ?? {},
    });
    ingested += 1;
    publish('event', doc.toJSON());
  }

  return ingested;
}
