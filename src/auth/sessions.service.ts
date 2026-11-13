import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Session } from '../generated/prisma/client';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'crypto';
import { PrismaService } from '../prisma/prisma.service';
import { SessionContext } from './auth.types';

const DAY_MS = 24 * 60 * 60 * 1000;

export interface IssuedRefreshToken {
  session: Session;
  token: string;
}

/**
 * Manages refresh sessions.
 *
 * A refresh token has the form `<sessionId>.<secret>`. Only a SHA-256 hash of the
 * secret is stored, so a database leak does not expose usable tokens. The secret is
 * 256 bits of randomness, which makes a fast hash appropriate here (unlike passwords).
 */
@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async create(userId: string, context: SessionContext, familyId = randomUUID()) {
    return this.issue(this.prisma, userId, familyId, context);
  }

  /**
   * Exchanges a refresh token for a new one.
   *
   * - Unknown, malformed or expired tokens are rejected.
   * - A token that was already rotated or revoked is treated as stolen: the whole
   *   session family is revoked, logging out every device that descended from it.
   * - The old session is revoked with a conditional update, so two concurrent
   *   refreshes with the same token cannot both succeed.
   */
  async rotate(rawToken: string, context: SessionContext): Promise<IssuedRefreshToken> {
    const session = await this.findByToken(rawToken);

    if (session.revokedAt) {
      await this.revokeFamily(session.familyId);
      throw new UnauthorizedException('Refresh token reuse detected');
    }
    if (session.expiresAt <= new Date()) {
      throw new UnauthorizedException('Refresh token expired');
    }

    return this.prisma.$transaction(async (tx) => {
      const claimed = await tx.session.updateMany({
        where: { id: session.id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      if (claimed.count === 0) {
        await tx.session.updateMany({
          where: { familyId: session.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
        throw new UnauthorizedException('Refresh token reuse detected');
      }

      const issued = await this.issue(tx, session.userId, session.familyId, context);
      await tx.session.update({
        where: { id: session.id },
        data: { replacedById: issued.session.id },
      });
      return issued;
    });
  }

  async revoke(sessionId: string, userId: string) {
    await this.prisma.session.updateMany({
      where: { id: sessionId, userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  async revokeAllForUser(userId: string) {
    const result = await this.prisma.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return result.count;
  }

  async listActive(userId: string) {
    return this.prisma.session.findMany({
      where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
      select: { id: true, userAgent: true, ipAddress: true, createdAt: true, expiresAt: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  private async revokeFamily(familyId: string) {
    await this.prisma.session.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  private async findByToken(rawToken: string): Promise<Session> {
    const [sessionId, secret] = rawToken.split('.');
    if (!sessionId || !secret) throw new UnauthorizedException('Invalid refresh token');

    const session = await this.prisma.session
      .findUnique({ where: { id: sessionId } })
      .catch(() => null);
    if (!session || !this.matches(secret, session.tokenHash)) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return session;
  }

  private async issue(
    client: Pick<PrismaService, 'session'>,
    userId: string,
    familyId: string,
    context: SessionContext,
  ): Promise<IssuedRefreshToken> {
    const secret = randomBytes(32).toString('base64url');
    const ttlDays = this.config.get<number>('REFRESH_TOKEN_TTL_DAYS', 30);

    const session = await client.session.create({
      data: {
        userId,
        familyId,
        tokenHash: SessionsService.hash(secret),
        expiresAt: new Date(Date.now() + ttlDays * DAY_MS),
        userAgent: context.userAgent?.slice(0, 255),
        ipAddress: context.ipAddress,
      },
    });
    return { session, token: `${session.id}.${secret}` };
  }

  private matches(secret: string, storedHash: string) {
    const candidate = Buffer.from(SessionsService.hash(secret), 'hex');
    const stored = Buffer.from(storedHash, 'hex');
    return candidate.length === stored.length && timingSafeEqual(candidate, stored);
  }

  static hash(secret: string) {
    return createHash('sha256').update(secret).digest('hex');
  }
}
