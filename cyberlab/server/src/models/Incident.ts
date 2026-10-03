import mongoose, { Schema, Document } from 'mongoose';

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';

export interface IIncident extends Document {
  id: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: IncidentStatus;
  detectedAt: Date;
  sourceIp: string;
  users: string[];
  assets: string[];
  eventIds: string[];
  findings: string[];
  attackPath: string[];
  confidence: number;
  recommendedActions: string[];
  mitreTactic: string | null;
  mitreTechnique: string | null;
}

const IncidentSchema = new Schema<IIncident>({
  id: { type: String, required: true, unique: true, index: true },
  title: { type: String, required: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  status: { type: String, enum: ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'], default: 'OPEN' },
  detectedAt: { type: Date, default: Date.now },
  sourceIp: { type: String },
  users: { type: [String], default: [] },
  assets: { type: [String], default: [] },
  eventIds: { type: [String], default: [] },
  findings: { type: [String], default: [] },
  attackPath: { type: [String], default: [] },
  confidence: { type: Number, default: 0 },
  recommendedActions: { type: [String], default: [] },
  mitreTactic: { type: String },
  mitreTechnique: { type: String },
});

export const Incident = mongoose.model<IIncident>('Incident', IncidentSchema, 'incidents');
