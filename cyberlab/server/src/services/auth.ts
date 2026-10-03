import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import { User, IUser } from '../models/User';
import { Session } from '../models/Session';

export interface TokenPayload {
  userId: string;
  email: string;
  role: string;
  tenantId: string;
}

export function hashPassword(password: string): string {
  return bcrypt.hashSync(password, 10);
}

export function comparePassword(password: string, hash: string): boolean {
  return bcrypt.compareSync(password, hash);
}

// A verified token payload already carries exp/iat. jsonwebtoken refuses to sign when both
// `options.expiresIn` and a payload `exp` are present, so re-signing (e.g. POST /api/auth/refresh)
// must strip the registered claims first.
function stripRegisteredClaims(payload: TokenPayload | Record<string, unknown>): TokenPayload {
  const source = payload as Record<string, unknown>;
  return {
    userId: source.userId as string,
    email: source.email as string,
    role: source.role as string,
    tenantId: source.tenantId as string,
  };
}

export function generateAccessToken(payload: TokenPayload | Record<string, unknown>): string {
  const options: jwt.SignOptions = { expiresIn: config.accessTokenExpiry as jwt.SignOptions['expiresIn'] };
  return jwt.sign(stripRegisteredClaims(payload), config.jwtSecret, options);
}

export function generateRefreshToken(payload: TokenPayload | Record<string, unknown>): string {
  const options: jwt.SignOptions = { expiresIn: config.refreshTokenExpiry as jwt.SignOptions['expiresIn'] };
  return jwt.sign(stripRegisteredClaims(payload), config.jwtRefreshSecret, options);
}

export function verifyAccessToken(token: string): TokenPayload | null {
  try {
    return jwt.verify(token, config.jwtSecret) as TokenPayload;
  } catch {
    return null;
  }
}

export function verifyRefreshToken(token: string): TokenPayload | null {
  try {
    return jwt.verify(token, config.jwtRefreshSecret) as TokenPayload;
  } catch {
    return null;
  }
}

export async function createSession(user: IUser, refreshToken: string, sourceIp: string, userAgent: string): Promise<void> {
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);
  await Session.create({
    id: uuidv4(),
    userId: user.id,
    tenantId: user.tenantId,
    refreshToken,
    sourceIp,
    userAgent,
    expiresAt,
    revoked: false,
  });
}

export async function revokeSession(refreshToken: string): Promise<void> {
  await Session.updateOne({ refreshToken }, { revoked: true });
}

export async function revokeAllUserSessions(userId: string): Promise<void> {
  await Session.updateMany({ userId, revoked: false }, { revoked: true });
}
