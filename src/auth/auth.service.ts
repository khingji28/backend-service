import { Injectable, ConflictException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
import { JwtPayload } from './types/jwt-payload.type';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(email: string, password: string) {
    console.log('start register....');
    // 1️⃣ เช็ค email ซ้ำ
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    // 2️⃣ hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3️⃣ สร้าง user
    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    // 4️⃣ return data
    return {
      id: user.id,
      email: user.email,
    };
  }

  async login(email: string, password: string) {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // 🎯 payload
    const payload = {
      sub: user.id,
      email: user.email,
    };

    // 🔐 access token (short-lived)
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
    });

    // 🔐 refresh token (long-lived)
    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: '7d',
    });

    // 🔥 hash ก่อนเก็บ
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    // 💾 save ลง DB
    await this.prisma.refreshToken.create({
      data: {
        token: hashedRefreshToken, // ❗ เก็บ hash
        userId: user.id,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revoked: false,
      },
    });

    return {
      accessToken,
      refreshToken, // 👈 ส่ง plain กลับ client
    };
  }

  async refreshToken(userId: number, refreshToken: string) {
    // 1️⃣ ดึง token ทั้งหมดของ user
    const tokens = await this.prisma.refreshToken.findMany({
      where: { userId },
    });

    // 2️⃣ หา token ที่ match (compare hash)
    let stored: (typeof tokens)[number] | null = null;

    for (const t of tokens) {
      const isMatch = await bcrypt.compare(refreshToken, t.token);
      if (isMatch) {
        stored = t;
        break;
      }
    }

    if (!stored) {
      throw new UnauthorizedException('Invalid token');
    }

    // 🚨 3️⃣ REUSE DETECTION (สำคัญมาก)
    if (stored.revoked) {
      // kill ทุก session
      await this.prisma.refreshToken.updateMany({
        where: { userId },
        data: { revoked: true },
      });

      throw new UnauthorizedException('Token reuse detected');
    }

    // 4️⃣ เช็ค expire
    if (stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Token expired');
    }

    // 5️⃣ verify JWT
    let payload: JwtPayload;
    try {
      payload = this.jwtService.verify<JwtPayload>(refreshToken);
    } catch {
      throw new UnauthorizedException('Invalid JWT');
    }

    // 6️⃣ ROTATION → revoke token เก่า
    await this.prisma.refreshToken.update({
      where: { id: stored.id }, // 👈 ใช้ id แทน token
      data: { revoked: true },
    });

    // 7️⃣ create access token
    const newAccessToken = this.jwtService.sign(
      {
        sub: payload.sub,
        email: payload.email,
      },
      {
        expiresIn: '15m',
      },
    );

    // 8️⃣ create refresh token ใหม่
    const newRefreshToken = this.jwtService.sign(
      {
        sub: payload.sub,
        email: payload.email,
      },
      {
        expiresIn: '7d',
      },
    );

    // 🔐 9️⃣ hash ก่อนเก็บ
    const hashedRefreshToken = await bcrypt.hash(newRefreshToken, 10);

    // 10️⃣ save ใหม่
    await this.prisma.refreshToken.create({
      data: {
        token: hashedRefreshToken,
        userId: payload.sub,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revoked: false,
      },
    });

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };
  }

  async logoutThisDevice(id: number, token: string) {
    await this.prisma.refreshToken.update({
      where: { token },
      data: { revoked: true },
    });

    return { message: 'Logged out from this device' };
  }

  async logoutAll(userId: number) {
    await this.prisma.refreshToken.updateMany({
      where: { userId },
      data: { revoked: true },
    });

    return { message: 'Logged out from all devices' };
  }
  async logoutOtherDevices(userId: number, currentToken: string) {
    await this.prisma.refreshToken.updateMany({
      where: {
        userId,
        token: {
          not: currentToken,
        },
      },
      data: { revoked: true },
    });

    return { message: 'Logged out from other devices' };
  }
}
