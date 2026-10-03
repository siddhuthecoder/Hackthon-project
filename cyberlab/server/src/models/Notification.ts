import mongoose, { Schema, Document } from 'mongoose';

export interface INotification extends Document {
  id: string;
  type: string;
  title: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  tenantId: string | null;
  incidentId: string | null;
  read: boolean;
  createdAt: Date;
}

const NotificationSchema = new Schema<INotification>({
  id: { type: String, required: true, unique: true, index: true },
  type: { type: String, required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
  tenantId: { type: String, default: null, index: true },
  incidentId: { type: String, default: null },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, index: true },
});

NotificationSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj._id;
  delete obj.__v;
  return obj;
};

export const Notification = mongoose.model<INotification>('Notification', NotificationSchema, 'notifications');
