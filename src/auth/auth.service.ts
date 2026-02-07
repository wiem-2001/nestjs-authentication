import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { CreateUserDto } from 'src/users/dtos/create-user-dto/create-user-dto';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './dtos/login/login';
import * as bcrypt from 'bcrypt';

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

  async refresh(userId: string) {
    const payload = { sub: userId };
    const access_token = this.jwtService.sign(payload);
    return { access_token };
  }
}

