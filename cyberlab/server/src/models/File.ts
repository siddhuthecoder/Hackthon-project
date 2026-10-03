import mongoose, { Schema, Document } from 'mongoose';

export interface IFile extends Document {
  id: string;
  filename: string;
  originalName: string;
  tenantId: string;
  userId: string;
  mimeType: string;
  size: number;
  uploadedAt: Date;
  validated: boolean;
}

const FileSchema = new Schema<IFile>({
  id: { type: String, required: true, unique: true, index: true },
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  tenantId: { type: String, required: true },
  userId: { type: String, required: true },
  mimeType: { type: String },
  size: { type: Number },
  uploadedAt: { type: Date, default: Date.now },
  validated: { type: Boolean, default: false },
});

export const FileMeta = mongoose.model<IFile>('File', FileSchema, 'files');
