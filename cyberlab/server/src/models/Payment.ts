import mongoose, { Schema, Document } from 'mongoose';

export interface IPayment extends Document {
  id: string;
  orderId: string;
  amount: number;
  status: 'pending' | 'completed' | 'failed' | 'refunded';
  method: 'card' | 'bank' | 'wallet';
  createdAt: Date;
}

const PaymentSchema = new Schema<IPayment>({
  id: { type: String, required: true, unique: true, index: true },
  orderId: { type: String, required: true, index: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'refunded'], default: 'pending' },
  method: { type: String, enum: ['card', 'bank', 'wallet'], default: 'card' },
  createdAt: { type: Date, default: Date.now },
});

export const Payment = mongoose.model<IPayment>('Payment', PaymentSchema);
