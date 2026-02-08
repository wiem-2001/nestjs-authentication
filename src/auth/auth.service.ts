import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { CreateUserDto } from 'src/users/dtos/create-user-dto';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './dtos/login';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService
  ) {}

  async register(userData: CreateUserDto) {
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    return this.usersService.create({ ...userData, password: hashedPassword });
  }

  async login(body: LoginDto) {
    const user = await this.usersService.findByEmail(body.email, true);
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const passwordValid = await bcrypt.compare(body.password, user.password);
    if (!passwordValid) throw new UnauthorizedException('Invalid credentials');

    const payload = { sub: user._id, email: user.email, roles: user.roles };
    const access_token = this.jwtService.sign(payload, { expiresIn: '1h' });
    const refresh_token = this.jwtService.sign(payload, { expiresIn: '7d' });
    
    
    const hashedRefreshToken = await bcrypt.hash(refresh_token, 10);
    await this.usersService.updateRefreshToken(user._id.toString(), hashedRefreshToken);
    
    return { access_token, refresh_token };
  }

  async refresh(userId: string, currentRefreshToken: string) {
    try {
      // Get user with refresh token from database
      const user = await this.usersService.getUserWithRefreshToken(userId);
      if (!user || !user.refreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Verify the provided token matches the stored hash
      const isRefreshTokenValid = await bcrypt.compare(currentRefreshToken, user.refreshToken);
      if (!isRefreshTokenValid) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Generate new tokens (token rotation)
      const payload = { sub: user._id, email: user.email, roles: user.roles };
      const access_token = this.jwtService.sign(payload, { expiresIn: '1h' });
      const refresh_token = this.jwtService.sign(payload, { expiresIn: '7d' });

      // Save new refresh token hash (rotate the token)
      const hashedRefreshToken = await bcrypt.hash(refresh_token, 10);
      await this.usersService.updateRefreshToken(userId, hashedRefreshToken);

      return { access_token, refresh_token };
    } catch (error) {
      if (error.statusCode === 401) throw error;
      throw new UnauthorizedException('Token refresh failed');
    }
  }

  async generateResetToken(email: string) {
  const user = await this.usersService.findByEmail(email, true);
  if (!user) throw new UnauthorizedException('User not found'); 

  const resetToken = crypto.randomBytes(32).toString('hex');
  user.resetPasswordToken = resetToken;
  user.resetPasswordExpires = new Date(Date.now() + 3600 * 1000); // 1 hour
  await user.save();

  return resetToken;
}

async validateResetToken(resetToken: string) {
  const user = await this.usersService.findOneByTokenAndExpirationDate(resetToken);
  if (!user) throw new UnauthorizedException('Invalid or expired token');
  return user;
}

async resetPassword(token: string, newPassword: string) {
  const user = await this.usersService.findOneByTokenAndExpirationDate(token);
    
  if (!user) throw new Error('Invalid or expired token');

  user.password = await bcrypt.hash(newPassword, 12);
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  return true;
}

}

