import mongoose, { Schema, Document } from 'mongoose';

export interface IAuditLog extends Document {
  actor: string;
  actorName: string;
  action: string;
  target: string | null;
  targetName: string | null;
  tenantId: string;
  oldValue: string | null;
  newValue: string | null;
  timestamp: Date;
  details: string | null;
}

const AuditLogSchema = new Schema<IAuditLog>({
  actor: { type: String, required: true },
  actorName: { type: String, required: true },
  action: { type: String, required: true },
  target: { type: String },
  targetName: { type: String },
  tenantId: { type: String, required: true },
  oldValue: { type: String },
  newValue: { type: String },
  timestamp: { type: Date, default: Date.now, index: true },
  details: { type: String },
});

export const AuditLog = mongoose.model<IAuditLog>('AuditLog', AuditLogSchema, 'audit_logs');
