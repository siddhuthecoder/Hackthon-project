import mongoose, { Schema, Document } from 'mongoose';

export interface IComment extends Document {
  id: string;
  productId: string;
  userId: string;
  userName: string;
  tenantId: string;
  content: string;
  sanitized: boolean;
  createdAt: Date;
}

const CommentSchema = new Schema<IComment>({
  id: { type: String, required: true, unique: true, index: true },
  productId: { type: String, required: true, index: true },
  userId: { type: String, required: true },
  userName: { type: String, required: true },
  tenantId: { type: String, required: true },
  content: { type: String, required: true },
  sanitized: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

export const Comment = mongoose.model<IComment>('Comment', CommentSchema, 'comments');
