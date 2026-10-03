import mongoose, { Schema, Document } from 'mongoose';

export interface ISession extends Document {
  id: string;
  userId: string;
  tenantId: string;
  refreshToken: string;
  sourceIp: string;
  userAgent: string;
  createdAt: Date;
  expiresAt: Date;
  revoked: boolean;
}

const SessionSchema = new Schema<ISession>({
  id: { type: String, required: true, unique: true, index: true },
  userId: { type: String, required: true, index: true },
  tenantId: { type: String, required: true },
  refreshToken: { type: String, required: true },
  sourceIp: { type: String },
  userAgent: { type: String },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  revoked: { type: Boolean, default: false },
});

export const Session = mongoose.model<ISession>('Session', SessionSchema, 'sessions');
