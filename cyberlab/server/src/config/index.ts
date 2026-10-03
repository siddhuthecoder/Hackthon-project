import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: parseInt(process.env.API_PORT || '3001', 10),
  mongoUri: process.env.MONGODB_URI || 'mongodb://mongodb:27017/sentinelforge',
  redisUrl: process.env.REDIS_URL || 'redis://redis:6379',
  jwtSecret: process.env.JWT_SECRET || 'demo_jwt_secret_not_for_production',
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'demo_refresh_secret_not_for_production',
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  internalServiceUrl: process.env.INTERNAL_SERVICE_URL || 'http://internal-service:8080',
  nodeEnv: process.env.NODE_ENV || 'development',
};

export type Config = typeof config;
