import mongoose, { Schema, Document } from 'mongoose';

export interface ITenant extends Document {
  id: string;
  name: string;
  plan: 'free' | 'pro' | 'enterprise';
  createdAt: Date;
}

const TenantSchema = new Schema<ITenant>({
  id: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  plan: { type: String, enum: ['free', 'pro', 'enterprise'], default: 'free' },
  createdAt: { type: Date, default: Date.now },
});

export const Tenant = mongoose.model<ITenant>('Tenant', TenantSchema);
