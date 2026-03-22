import { Body, Controller, Post, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { UseGuards, Get, Req } from '@nestjs/common';
import { JwtAuthGuard } from './jwt/jwt.guard';
import type { RequestWithUser } from './types/request-with-user.type';
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() body: RegisterDto) {
    return this.authService.register(body.email, body.password);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() body: LoginDto) {
    return this.authService.login(body.email, body.password);
  }

  @Post('refresh')
  @UseGuards(JwtAuthGuard)
  refresh(@Req() req: RequestWithUser, @Body() body: { refreshToken: string }) {
    return this.authService.refreshToken(req.user.id, body.refreshToken);
  }
  @Post('logout')
  @UseGuards(JwtAuthGuard)
  logout(@Req() req: RequestWithUser, @Body() body: { refreshToken: string }) {
    return this.authService.logoutThisDevice(req.user.id, body.refreshToken);
  }

  @Post('logout-all')
  @UseGuards(JwtAuthGuard)
  logoutAll(@Req() req: RequestWithUser) {
    return this.authService.logoutAll(req.user.id);
  }
  @Post('logout-others')
  @UseGuards(JwtAuthGuard)
  logoutOthers(
    @Req() req: RequestWithUser,
    @Body() body: { refreshToken: string },
  ) {
    return this.authService.logoutOtherDevices(req.user.id, body.refreshToken);
  }
  @Get('me')
  @UseGuards(JwtAuthGuard)
  getMe(@Req() req: RequestWithUser) {
    return {
      id: req.user.id,
      publicId: req.user.publicId,
      email: req.user.email,
    };
  }
}
