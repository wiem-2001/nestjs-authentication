import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { JwtGuard } from './guards/jwt-guard/jwt-guard';
import { RefreshGuard } from './guards/refresh-guard/refresh-guard';
import { CreateUserDto } from 'src/users/dtos/create-user-dto/create-user-dto';
import { LoginDto } from './dtos/login/login';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

        @Post('register')
async register(@Body() userData: CreateUserDto) {
  return this.authService.register(userData);
}

@Post('login')
async login(@Body() body: LoginDto) {
  return this.authService.login(body);
}

@UseGuards(RefreshGuard)
@Post('refresh')
async refresh(@Req() req: any) {
  return this.authService.refresh(req.user.userId);
}

@UseGuards(JwtGuard)
@Get('profile')
getProfile(@Req() req: any) {
  return {
    userId: req.user.userId,
    email: req.user.email,
    roles: req.user.roles,
  };
}}