import { assertStartupSafe, config } from './config';
import { connectDb, disconnectDb } from './db/connection';
import { startLiveLoop, stopLiveLoop } from './modules/live/loop';
import { startRescanScheduler, stopRescanScheduler } from './modules/scheduler/rescan';
import { buildServer } from './server';

async function main(): Promise<void> {
  assertStartupSafe();
  await connectDb();
  const app = await buildServer();
  await app.listen({ port: config.port, host: '0.0.0.0' });
  app.log.info(`SentinelForge API listening on :${config.port}`);
  startLiveLoop();
  startRescanScheduler();

  const shutdown = async (): Promise<void> => {
    stopLiveLoop();
    stopRescanScheduler();
    await app.close();
    await disconnectDb();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch(err => {
  console.error('[startup] fatal:', err instanceof Error ? err.message : err);
  process.exit(1);
});
