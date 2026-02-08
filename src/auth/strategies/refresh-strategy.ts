import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-jwt';
import { Request } from 'express';

@Injectable()
export class RefreshStrategy extends PassportStrategy(Strategy, 'refresh') {

  constructor() {
    super({
      jwtFromRequest: (req: Request) => {
        return req.cookies?.refreshToken || null;
      },
      secretOrKey: process.env.JWT_SECRET || 'supersecret',
    });
  }

  async validate(payload: any) {
    return {
      userId: payload.sub,
      email: payload.email,
      roles: payload.roles,
    };
  }
}
