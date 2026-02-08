import { Body, Controller, Get, Post, Req, UseGuards, Res, UnauthorizedException } from '@nestjs/common';
import { JwtGuard } from './guards/jwt-guard';
import { RefreshGuard } from './guards/refresh-guard';
import { CreateUserDto } from 'src/users/dtos/create-user-dto';
import { LoginDto } from './dtos/login';
import { AuthService } from './auth.service';
import { UsersService } from 'src/users/users.service';
import { ForgotPasswordDto } from './dtos/forgot-password';
import { ResetPasswordDto } from './dtos/reset-password';
import { VerifyResetLinkDto } from './dtos/verify-reset-link.dto';
import { EmailService } from 'src/email/email.service';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private usersService: UsersService,
    private emailService: EmailService
  ) {}

        @Post('register')
async register(@Body() userData: CreateUserDto) {
  return this.authService.register(userData);
}

@Post('login')
async login(@Body() body: LoginDto, @Res() res: any) {
  const tokens = await this.authService.login(body);
  
  // Set httpOnly cookies
  res.cookie('accessToken', tokens.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000, // 1 hour
  });
  
  res.cookie('refreshToken', tokens.refresh_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 604800000, // 7 days
  });
  
  return res.json({ message: 'Login successful' });
}

@UseGuards(RefreshGuard)
@Post('refresh')
async refresh(@Req() req: any, @Res() res: any) {
  const currentRefreshToken = req.cookies?.refreshToken;
  if (!currentRefreshToken) {
    throw new UnauthorizedException('No refresh token provided');
  }

  const tokens = await this.authService.refresh(req.user.userId, currentRefreshToken);
  
  // Set new accessToken cookie
  res.cookie('accessToken', tokens.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000, // 1 hour
  });

  // Set new refreshToken cookie (token rotation)
  res.cookie('refreshToken', tokens.refresh_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 604800000, // 7 days
  });
  
  return res.json({ message: 'Token refreshed and rotated' });
}

@UseGuards(JwtGuard)
@Get('profile')
getProfile(@Req() req: any) {
  return {
    userId: req.user.userId,
    email: req.user.email,
    roles: req.user.roles,
  };
  
}

@Post('forgot-password')
async forgotPassword(@Body() dto: ForgotPasswordDto) {
  const token = await this.authService.generateResetToken(dto.email);
  if (token) {
    
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password#token=${token}`;
  await this.emailService.sendMail(
    dto.email,
    'Password Reset Request',
    `Click here to reset your password: ${resetUrl}`,
    `<p>Click <a href="${resetUrl}">here</a> to reset your password</p>`
  );
  console.log('Reset token:', token);
  console.log('Reset URL:', resetUrl);
  }
  return { message: 'If that email exists, a reset link was sent.' };
}

@Post('verify-reset-link')
async verifyResetLink(@Body() dto: VerifyResetLinkDto, @Res() res: any) {
  await this.authService.validateResetToken(dto.resetSessionToken);
  
  res.cookie('resetSession', dto.resetSessionToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000, 
  });

  return res.json({ message: 'Ready to reset password' });
}

@Post('reset-password')
async resetPassword(@Body() dto: ResetPasswordDto, @Req() req: any, @Res() res: any) {
  const resetToken = req.cookies?.resetSession;
  if (!resetToken) throw new UnauthorizedException('No valid reset session');
  
  await this.authService.resetPassword(resetToken, dto.newPassword);
  
  res.clearCookie('resetSession');
  return res.json({ message: 'Password reset successful' });
}

@UseGuards(JwtGuard)
@Post('logout')
async logout(@Req() req: any, @Res() res: any) {
  // Clear refresh token from database (invalidate all tokens)
  await this.usersService.clearRefreshToken(req.user.userId);
  
  // Clear cookies
  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');
  res.clearCookie('resetSession');
  return res.json({ message: 'Logout successful' });
}
}