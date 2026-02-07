import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt-strategry/jwt-strategry';
import { RefreshStrategy } from './strategies/refresh-strategy/refresh-strategy';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { JwtGuard } from './guards/jwt-guard/jwt-guard';
import { RefreshGuard } from './guards/refresh-guard/refresh-guard';

@Module({
    imports: [
    UsersModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      secret:'supersecret',
      signOptions: { expiresIn: '1h' },
    }),
  ],
  providers: [JwtStrategy, RefreshStrategy, JwtGuard, RefreshGuard, AuthService],
  controllers: [AuthController]
})
export class AuthModule {}
