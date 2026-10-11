import mongoose from 'mongoose';
import { config } from '../config';

let connected = false;

export async function connectDb(): Promise<void> {
  if (connected) return;
  await mongoose.connect(config.mongoUri);
  connected = true;
}

export async function disconnectDb(): Promise<void> {
  if (!connected) return;
  await mongoose.disconnect();
  connected = false;
}

export async function dbHealthy(): Promise<boolean> {
  return mongoose.connection.readyState === 1;
}
