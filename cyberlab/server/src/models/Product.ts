import mongoose, { Schema, Document } from 'mongoose';

export interface IProduct extends Document {
  id: string;
  name: string;
  description: string;
  price: number;
  category: string;
  tenantId: string;
  stock: number;
  createdAt: Date;
}

const ProductSchema = new Schema<IProduct>({
  id: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  category: { type: String },
  tenantId: { type: String, required: true, index: true },
  stock: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

export const Product = mongoose.model<IProduct>('Product', ProductSchema);
