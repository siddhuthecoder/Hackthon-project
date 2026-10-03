import mongoose from 'mongoose';
import { config } from '../config';

export async function connectDB(): Promise<void> {
  try {
    await mongoose.connect(config.mongoUri);
    console.log('[DB] Connected to MongoDB');
  } catch (err) {
    console.error('[DB] Connection failed:', err);
    process.exit(1);
  }
}

export async function disconnectDB(): Promise<void> {
  await mongoose.disconnect();
  console.log('[DB] Disconnected');
}
