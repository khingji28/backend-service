import { Injectable, ConflictException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async register(email: string, password: string) {
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
}
