import mongoose, { Schema, Document } from 'mongoose';

export interface ICustomer extends Document {
  id: string;
  name: string;
  email: string;
  company: string;
  phone: string;
  tenantId: string;
  createdAt: Date;
}

const CustomerSchema = new Schema<ICustomer>({
  id: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  email: { type: String, required: true },
  company: { type: String },
  phone: { type: String },
  tenantId: { type: String, required: true, index: true },
  createdAt: { type: Date, default: Date.now },
});

CustomerSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj._id;
  delete obj.__v;
  return obj;
};

export const Customer = mongoose.model<ICustomer>('Customer', CustomerSchema, 'customers');
