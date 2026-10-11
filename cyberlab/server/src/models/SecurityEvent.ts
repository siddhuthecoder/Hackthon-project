import mongoose, { Schema, Document } from 'mongoose';

export type SecurityEventType =
  | 'AUTH_SUCCESS' | 'AUTH_FAILURE' | 'PASSWORD_RESET' | 'SESSION_CREATED' | 'SESSION_REVOKED'
  | 'API_REQUEST' | 'API_ERROR' | 'AUTHORIZATION_FAILURE' | 'PRIVILEGE_CHANGE' | 'ADMIN_ACTION'
  | 'DATA_ACCESS' | 'BULK_DATA_ACCESS' | 'CROSS_TENANT_ACCESS_ATTEMPT'
  | 'FILE_UPLOAD' | 'FILE_DOWNLOAD' | 'SUSPICIOUS_REQUEST' | 'RATE_LIMIT_TRIGGERED'
  | 'PAYMENT_CREATED' | 'PAYMENT_UPDATED' | 'REFUND_CREATED' | 'SECURITY_FINDING_TRIGGERED'
  | 'DATA_EXPORT' | 'SUSPICIOUS_ACTIVITY' | 'CROSS_RESOURCE_ACCESS' | 'CANARY_TRIGGERED';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface ISecurityEvent extends Document {
  timestamp: Date;
  eventType: SecurityEventType;
  severity: Severity;
  userId: string | null;
  tenantId: string | null;
  sourceIp: string;
  endpoint: string;
  method: string;
  userAgent: string;
  requestId: string;
  mitreTechnique: string | null;
  metadata: Record<string, unknown>;
}

const SecurityEventSchema = new Schema<ISecurityEvent>({
  timestamp: { type: Date, default: Date.now, index: true },
  eventType: { type: String, required: true, index: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low', index: true },
  userId: { type: String, index: true },
  tenantId: { type: String, index: true },
  sourceIp: { type: String, index: true },
  endpoint: { type: String },
  method: { type: String },
  userAgent: { type: String },
  requestId: { type: String, index: true },
  mitreTechnique: { type: String, default: null },
  metadata: { type: Schema.Types.Mixed, default: {} },
});

SecurityEventSchema.index({ eventType: 1, sourceIp: 1, timestamp: -1 });
SecurityEventSchema.index({ userId: 1, timestamp: -1 });

SecurityEventSchema.methods.toJSON = function () {
  const obj = this.toObject();
  obj.id = String(obj._id);
  delete obj._id;
  delete obj.__v;
  return obj;
};

export const SecurityEvent = mongoose.model<ISecurityEvent>('SecurityEvent', SecurityEventSchema, 'security_events');
