import { Role } from '../generated/prisma/client';

export interface AccessTokenPayload {
  sub: string;
  email: string;
  role: Role;
  sid: string;
}

export interface AuthUser {
  id: string;
  email: string;
  role: Role;
  sessionId: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: string;
}

export interface SessionContext {
  userAgent?: string;
  ipAddress?: string;
}
