import mongoose, { Schema, Document } from 'mongoose';

export interface IOrderItem {
  productId: string;
  name: string;
  quantity: number;
  price: number;
}

export interface IOrder extends Document {
  id: string;
  orderNumber: string;
  customerId: string;
  customerName: string;
  tenantId: string;
  items: IOrderItem[];
  total: number;
  status: 'pending' | 'paid' | 'shipped' | 'delivered' | 'cancelled' | 'refunded';
  createdAt: Date;
}

const OrderItemSchema = new Schema<IOrderItem>({
  productId: String,
  name: String,
  quantity: Number,
  price: Number,
});

const OrderSchema = new Schema<IOrder>({
  id: { type: String, required: true, unique: true, index: true },
  orderNumber: { type: String, required: true },
  customerId: { type: String, required: true, index: true },
  customerName: { type: String },
  tenantId: { type: String, required: true, index: true },
  items: [OrderItemSchema],
  total: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'paid', 'shipped', 'delivered', 'cancelled', 'refunded'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});

export const Order = mongoose.model<IOrder>('Order', OrderSchema);
