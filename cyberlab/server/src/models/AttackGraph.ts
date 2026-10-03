import mongoose, { Schema, Document } from 'mongoose';

export interface IAttackGraphNode {
  id: string;
  type: 'USER' | 'IP' | 'DEVICE' | 'API' | 'ENDPOINT' | 'VULNERABILITY' | 'ASSET' | 'DATABASE' | 'TENANT';
  label: string;
  metadata?: Record<string, string>;
}

export interface IAttackGraphEdge {
  from: string;
  to: string;
  type: string;
}

export interface IAttackGraph extends Document {
  nodes: IAttackGraphNode[];
  edges: IAttackGraphEdge[];
  attackPath: string[];
}

const NodeSchema = new Schema({
  id: { type: String, required: true },
  type: { type: String, required: true },
  label: { type: String, required: true },
  metadata: { type: Map, of: String },
}, { _id: false });

const EdgeSchema = new Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  type: { type: String, required: true },
}, { _id: false });

const AttackGraphSchema = new Schema<IAttackGraph>({
  nodes: { type: [NodeSchema], default: [] },
  edges: { type: [EdgeSchema], default: [] },
  attackPath: { type: [String], default: [] },
});

export const AttackGraph = mongoose.model<IAttackGraph>('AttackGraph', AttackGraphSchema, 'attack_graphs');
