import mongoose, { Schema, Document } from 'mongoose';

export type Role = 'SUPER_ADMIN' | 'TENANT_ADMIN' | 'MANAGER' | 'STAFF' | 'USER';

export interface IUser extends Document {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  role: Role;
  tenantId: string;
  active: boolean;
  lastLogin: Date | null;
  createdAt: Date;
  phone?: string;
  isAdmin?: boolean;
}

const UserSchema = new Schema<IUser>({
  id: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['SUPER_ADMIN', 'TENANT_ADMIN', 'MANAGER', 'STAFF', 'USER'], default: 'USER' },
  tenantId: { type: String, required: true, index: true },
  active: { type: Boolean, default: true },
  lastLogin: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  phone: { type: String },
  isAdmin: { type: Boolean, default: false },
});

UserSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.passwordHash;
  delete obj._id;
  delete obj.__v;
  return obj;
};

export const User = mongoose.model<IUser>('User', UserSchema);
