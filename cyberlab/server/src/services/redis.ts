import { createClient, RedisClientType } from 'redis';
import { config } from '../config';

let redisClient: RedisClientType | null = null;

export async function connectRedis(): Promise<void> {
  try {
    redisClient = createClient({ url: config.redisUrl });
    redisClient.on('error', (err) => console.error('[Redis] Error:', err));
    await redisClient.connect();
    console.log('[Redis] Connected');
  } catch (err) {
    console.error('[Redis] Connection failed:', err);
  }
}

export function getRedis(): RedisClientType | null {
  return redisClient;
}

export async function publishEvent(channel: string, event: Record<string, unknown>): Promise<void> {
  if (!redisClient) return;
  try {
    await redisClient.publish(channel, JSON.stringify(event));
  } catch (err) {
    console.error('[Redis] Publish failed:', err);
  }
}

export async function disconnectRedis(): Promise<void> {
  if (redisClient) {
    await redisClient.quit();
    console.log('[Redis] Disconnected');
  }
}
