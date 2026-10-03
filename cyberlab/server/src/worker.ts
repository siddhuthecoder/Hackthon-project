import { v4 as uuidv4 } from 'uuid';
import { createClient } from 'redis';
import { config } from './config';
import { connectDB, disconnectDB } from './services/database';
import { connectRedis, disconnectRedis } from './services/redis';
import { runDetectionRules, startDetectionEngine } from './services/detectionEngine';
import { Incident } from './models/Incident';
import { Notification } from './models/Notification';
import { Session } from './models/Session';

const NOTIFY_INTERVAL_MS = 10_000;
const SESSION_CLEANUP_MS = 60 * 60 * 1000;

async function notifyNewIncidents(): Promise<void> {
  const since = new Date(Date.now() - 2 * NOTIFY_INTERVAL_MS);
  const incidents = await Incident.find({ detectedAt: { $gte: since } });
  for (const incident of incidents) {
    const exists = await Notification.exists({ incidentId: incident.id });
    if (exists) continue;
    await Notification.create({
      id: `notif-${uuidv4().slice(0, 8)}`,
      type: 'INCIDENT',
      title: incident.title,
      message: `${incident.severity.toUpperCase()} incident ${incident.id} from ${incident.sourceIp}`,
      severity: incident.severity,
      tenantId: null,
      incidentId: incident.id,
      read: false,
      createdAt: new Date(),
    });
    console.log(JSON.stringify({ stream: 'worker', job: 'notify', incidentId: incident.id, title: incident.title }));
  }
}

async function cleanupSessions(): Promise<void> {
  const result = await Session.deleteMany({ expiresAt: { $lt: new Date() } });
  console.log(JSON.stringify({ stream: 'worker', job: 'session-cleanup', removed: result.deletedCount }));
}

async function subscribeToSecurityStream(): Promise<void> {
  const subscriber = createClient({ url: config.redisUrl });
  subscriber.on('error', err => console.error('[Worker] Redis subscriber error:', err));
  await subscriber.connect();
  await subscriber.subscribe('security-events', message => {
    try {
      const event = JSON.parse(message) as { severity?: string; eventType?: string; sourceIp?: string; endpoint?: string };
      if (event.severity === 'critical' || event.severity === 'high') {
        console.log(JSON.stringify({ stream: 'soc-consumer', severity: event.severity, eventType: event.eventType, sourceIp: event.sourceIp, endpoint: event.endpoint }));
      }
    } catch (err) {
      console.error('[Worker] Bad stream message:', err);
    }
  });
  console.log('[Worker] Subscribed to Redis channel security-events');
}

async function start(): Promise<void> {
  await connectDB();
  await connectRedis();
  await startDetectionEngine();
  await subscribeToSecurityStream();
  await runDetectionRules();

  setInterval(() => {
    notifyNewIncidents().catch(err => console.error('[Worker] notify failed:', err));
  }, NOTIFY_INTERVAL_MS);
  setInterval(() => {
    cleanupSessions().catch(err => console.error('[Worker] cleanup failed:', err));
  }, SESSION_CLEANUP_MS);

  console.log('[Worker] Background jobs started: detection, notifications, session cleanup, SOC stream consumer');
}

process.on('SIGTERM', async () => {
  await disconnectDB();
  await disconnectRedis();
  process.exit(0);
});

start().catch(err => {
  console.error('[Worker] Fatal:', err);
  process.exit(1);
});
