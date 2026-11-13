import { UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { SessionsService } from './sessions.service';

describe('SessionsService', () => {
  const secret = 'a-very-random-secret';
  const baseSession = {
    id: 'session-1',
    userId: 'user-1',
    familyId: 'family-1',
    tokenHash: SessionsService.hash(secret),
    expiresAt: new Date(Date.now() + 60_000),
    revokedAt: null as Date | null,
  };

  let prisma: {
    session: { findUnique: jest.Mock; updateMany: jest.Mock; create: jest.Mock; update: jest.Mock };
    $transaction: jest.Mock;
  };
  let service: SessionsService;

  beforeEach(() => {
    prisma = {
      session: {
        findUnique: jest.fn(),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        create: jest
          .fn()
          .mockImplementation(({ data }) => Promise.resolve({ id: 'session-2', ...data })),
        update: jest.fn(),
      },
      $transaction: jest.fn((fn) => fn(prisma)),
    };
    const config = { get: jest.fn().mockReturnValue(30) } as unknown as ConfigService;
    service = new SessionsService(prisma as unknown as PrismaService, config);
  });

  it('stores only a hash of the refresh secret', async () => {
    const { token, session } = await service.create('user-1', {});
    const [, rawSecret] = token.split('.');
    expect(session.tokenHash).toBe(SessionsService.hash(rawSecret));
    expect(session.tokenHash).not.toContain(rawSecret);
  });

  it('rotates a valid token within the same family', async () => {
    prisma.session.findUnique.mockResolvedValue(baseSession);
    const { session } = await service.rotate(`session-1.${secret}`, {});
    expect(session.familyId).toBe('family-1');
    expect(prisma.session.update).toHaveBeenCalledWith({
      where: { id: 'session-1' },
      data: { replacedById: 'session-2' },
    });
  });

  it('rejects a token with the wrong secret', async () => {
    prisma.session.findUnique.mockResolvedValue(baseSession);
    await expect(service.rotate('session-1.wrong', {})).rejects.toThrow(UnauthorizedException);
  });

  it('rejects malformed tokens without querying the database', async () => {
    await expect(service.rotate('not-a-token', {})).rejects.toThrow(UnauthorizedException);
    expect(prisma.session.findUnique).not.toHaveBeenCalled();
  });

  it('revokes the whole family when a rotated token is reused', async () => {
    prisma.session.findUnique.mockResolvedValue({ ...baseSession, revokedAt: new Date() });
    await expect(service.rotate(`session-1.${secret}`, {})).rejects.toThrow('reuse');
    expect(prisma.session.updateMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { familyId: 'family-1', revokedAt: null } }),
    );
  });

  it('treats a lost race on the same token as reuse', async () => {
    prisma.session.findUnique.mockResolvedValue(baseSession);
    prisma.session.updateMany.mockResolvedValueOnce({ count: 0 });
    await expect(service.rotate(`session-1.${secret}`, {})).rejects.toThrow('reuse');
  });

  it('rejects expired tokens', async () => {
    prisma.session.findUnique.mockResolvedValue({ ...baseSession, expiresAt: new Date(0) });
    await expect(service.rotate(`session-1.${secret}`, {})).rejects.toThrow('expired');
  });
});
