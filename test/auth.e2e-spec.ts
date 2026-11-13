import 'dotenv/config';
import { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import * as argon2 from 'argon2';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from '../src/app.module';
import { Role } from '../src/generated/prisma/client';
import { PrismaService } from '../src/prisma/prisma.service';
import { setupApp } from '../src/setup-app';

describe('Auth flow (e2e)', () => {
  let app: INestApplication<App>;
  let prisma: PrismaService;
  const password = 'Str0ngPassw0rd!';

  const register = (email: string) =>
    request(app.getHttpServer()).post('/auth/register').send({ email, password });
  const login = (email: string, pass = password) =>
    request(app.getHttpServer()).post('/auth/login').send({ email, password: pass });
  const refresh = (refreshToken: string) =>
    request(app.getHttpServer()).post('/auth/refresh').send({ refreshToken });
  const authed = (method: 'get' | 'post' | 'patch', url: string, token: string) =>
    request(app.getHttpServer())[method](url).set('Authorization', `Bearer ${token}`);

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();

    app = moduleRef.createNestApplication();
    setupApp(app);
    await app.init();
    prisma = app.get(PrismaService);
  });

  beforeEach(async () => {
    await prisma.session.deleteMany();
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await app.close();
  });

  it('registers a user and returns a token pair', async () => {
    const res = await register('Jane@Example.com').expect(201);
    expect(res.body).toMatchObject({ tokenType: 'Bearer', expiresIn: expect.any(String) });
    expect(res.body.refreshToken).toMatch(/^[0-9a-f-]{36}\..+$/);

    const me = await authed('get', '/users/me', res.body.accessToken).expect(200);
    expect(me.body).toMatchObject({ email: 'jane@example.com', role: 'USER' });
    expect(me.body.passwordHash).toBeUndefined();
  });

  it('rejects duplicate emails and weak passwords', async () => {
    await register('jane@example.com').expect(201);
    await register('jane@example.com').expect(409);
    await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email: 'weak@example.com', password: 'short' })
      .expect(400);
  });

  it('rejects unknown fields in the request body', async () => {
    await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email: 'x@example.com', password, role: 'ADMIN' })
      .expect(400);
  });

  it('returns the same error for a wrong password and an unknown email', async () => {
    await register('jane@example.com').expect(201);
    const wrongPassword = await login('jane@example.com', 'Wr0ngPassword!').expect(401);
    const unknownEmail = await login('nobody@example.com').expect(401);
    expect(wrongPassword.body.message).toBe(unknownEmail.body.message);
  });

  it('requires an access token on protected routes', async () => {
    await request(app.getHttpServer()).get('/users/me').expect(401);
    await authed('get', '/users/me', 'not-a-jwt').expect(401);
  });

  it('rotates refresh tokens and detects reuse', async () => {
    const { body: first } = await register('jane@example.com').expect(201);

    const { body: second } = await refresh(first.refreshToken).expect(200);
    expect(second.refreshToken).not.toBe(first.refreshToken);

    // Replaying the old token revokes the whole family, including the fresh one.
    await refresh(first.refreshToken).expect(401);
    await refresh(second.refreshToken).expect(401);
  });

  it('keeps sessions from separate logins independent', async () => {
    await register('jane@example.com').expect(201);
    const { body: laptop } = await login('jane@example.com').expect(200);
    const { body: phone } = await login('jane@example.com').expect(200);

    await refresh(laptop.refreshToken).expect(200);
    await refresh(laptop.refreshToken).expect(401); // reuse on the laptop family
    await refresh(phone.refreshToken).expect(200); // phone family is unaffected
  });

  it('logs out the current session only', async () => {
    const { body: a } = await register('jane@example.com').expect(201);
    const { body: b } = await login('jane@example.com').expect(200);

    await authed('post', '/auth/logout', a.accessToken).expect(204);
    await refresh(a.refreshToken).expect(401);
    await refresh(b.refreshToken).expect(200);
  });

  it('logs out every session', async () => {
    const { body: a } = await register('jane@example.com').expect(201);
    const { body: b } = await login('jane@example.com').expect(200);

    const res = await authed('post', '/auth/logout-all', a.accessToken).expect(200);
    expect(res.body.revokedSessions).toBe(2);
    await refresh(a.refreshToken).expect(401);
    await refresh(b.refreshToken).expect(401);
  });

  it('lists active sessions', async () => {
    const { body } = await register('jane@example.com').expect(201);
    await login('jane@example.com').expect(200);
    const res = await authed('get', '/auth/sessions', body.accessToken).expect(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0].tokenHash).toBeUndefined();
  });

  describe('role-based access control', () => {
    let adminToken: string;

    beforeEach(async () => {
      await prisma.user.create({
        data: {
          email: 'admin@example.com',
          passwordHash: await argon2.hash(password),
          role: Role.ADMIN,
        },
      });
      adminToken = (await login('admin@example.com').expect(200)).body.accessToken;
    });

    it('forbids regular users from admin routes', async () => {
      const { body } = await register('jane@example.com').expect(201);
      await authed('get', '/users', body.accessToken).expect(403);
    });

    it('lets admins list users', async () => {
      await register('jane@example.com').expect(201);
      const res = await authed('get', '/users', adminToken).expect(200);
      expect(res.body.map((u: { email: string }) => u.email)).toEqual([
        'admin@example.com',
        'jane@example.com',
      ]);
    });

    it('revokes sessions when a role changes', async () => {
      const { body: jane } = await register('jane@example.com').expect(201);
      const { body: profile } = await authed('get', '/users/me', jane.accessToken).expect(200);

      await authed('patch', `/users/${profile.id}/role`, adminToken)
        .send({ role: 'ADMIN' })
        .expect(200);

      await refresh(jane.refreshToken).expect(401);
      const { body: relogin } = await login('jane@example.com').expect(200);
      await authed('get', '/users', relogin.accessToken).expect(200);
    });

    it('validates role updates', async () => {
      await authed('patch', '/users/not-a-uuid/role', adminToken)
        .send({ role: 'ADMIN' })
        .expect(400);
      await authed('patch', '/users/7b1e3c2a-1d2f-4a5b-9c8d-0e1f2a3b4c5d/role', adminToken)
        .send({ role: 'OWNER' })
        .expect(400);
      await authed('patch', '/users/7b1e3c2a-1d2f-4a5b-9c8d-0e1f2a3b4c5d/role', adminToken)
        .send({ role: 'ADMIN' })
        .expect(404);
    });
  });

  it('exposes a public health check', async () => {
    await request(app.getHttpServer()).get('/health').expect(200, { status: 'ok' });
  });
});
