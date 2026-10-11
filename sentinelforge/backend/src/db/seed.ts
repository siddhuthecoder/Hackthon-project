import bcrypt from 'bcryptjs';
import { config, assertSeedCredentialsPresent, assertStartupSafe } from '../config';
import { connectDb, disconnectDb } from './connection';
import { Organization, User } from './models';
import { newId } from '../lib/util';

async function seed(): Promise<void> {
  assertStartupSafe();
  assertSeedCredentialsPresent();
  await connectDb();

  let org = await Organization.findOne({ name: 'SentinelForge Demo' });
  if (!org) {
    org = await Organization.create({ _id: newId('org'), name: 'SentinelForge Demo' });
  }

  const accounts = [
    { email: config.adminEmail, password: config.adminPassword as string, name: 'Admin', role: 'admin' as const },
    { email: config.analystEmail, password: config.analystPassword as string, name: 'Analyst', role: 'analyst' as const },
  ];

  for (const acc of accounts) {
    const existing = await User.findOne({ email: acc.email.toLowerCase() });
    const passwordHash = bcrypt.hashSync(acc.password, 10);
    if (existing) {
      existing.set({ passwordHash, name: acc.name, role: acc.role, active: true });
      await existing.save();
      console.log(`[seed] updated user ${acc.email}`);
    } else {
      await User.create({ _id: newId('usr'), organizationId: org.id, email: acc.email.toLowerCase(), name: acc.name, passwordHash, role: acc.role, active: true });
      console.log(`[seed] created user ${acc.email}`);
    }
  }

  console.log('[seed] done');
  await disconnectDb();
}

seed().catch(err => {
  console.error('[seed] failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
