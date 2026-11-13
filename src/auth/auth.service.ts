import { ConflictException, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '../generated/prisma/client';
import * as argon2 from 'argon2';
import { UsersService } from '../users/users.service';
import { AccessTokenPayload, SessionContext, TokenPair } from './auth.types';
import { LoginDto, RegisterDto } from './dto/credentials.dto';
import { SessionsService } from './sessions.service';

@Injectable()
export class AuthService {
  /**
   * Hash compared against when the email is unknown, so a failed login takes the
   * same time whether or not the account exists (prevents user enumeration).
   */
  private readonly dummyHash = argon2.hash('timing-equalisation-placeholder');

  constructor(
    private readonly users: UsersService,
    private readonly sessions: SessionsService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async register(dto: RegisterDto, context: SessionContext): Promise<TokenPair> {
    if (await this.users.findByEmail(dto.email)) {
      throw new ConflictException('Email is already registered');
    }
    const user = await this.users.create(dto.email, await argon2.hash(dto.password));
    return this.startSession(user, context);
  }

  async login(dto: LoginDto, context: SessionContext): Promise<TokenPair> {
    const user = await this.users.findByEmail(dto.email);
    const valid = await argon2.verify(user?.passwordHash ?? (await this.dummyHash), dto.password);
    if (!user || !valid) throw new UnauthorizedException('Invalid email or password');
    return this.startSession(user, context);
  }

  async refresh(refreshToken: string, context: SessionContext): Promise<TokenPair> {
    const { session, token } = await this.sessions.rotate(refreshToken, context);
    const user = await this.users.findById(session.userId);
    if (!user) throw new UnauthorizedException('User no longer exists');
    return this.buildTokenPair(user, session.id, token);
  }

  logout(sessionId: string, userId: string) {
    return this.sessions.revoke(sessionId, userId);
  }

  logoutEverywhere(userId: string) {
    return this.sessions.revokeAllForUser(userId);
  }

  private async startSession(user: User, context: SessionContext) {
    const { session, token } = await this.sessions.create(user.id, context);
    return this.buildTokenPair(user, session.id, token);
  }

  private async buildTokenPair(
    user: User,
    sessionId: string,
    refreshToken: string,
  ): Promise<TokenPair> {
    const payload: AccessTokenPayload = {
      sub: user.id,
      email: user.email,
      role: user.role,
      sid: sessionId,
    };
    return {
      accessToken: await this.jwt.signAsync(payload),
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: this.config.get<string>('JWT_ACCESS_TTL', '15m'),
    };
  }
}
