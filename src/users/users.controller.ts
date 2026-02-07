import { Auth } from './../../node_modules/mongodb/src/mongo_client';
import { Controller, Get, NotFoundException, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';

@Controller('users')
export class UsersController {
    constructor(private readonly userService:UsersService) {}

  @UseGuards(AuthGuard('jwt'))
  @Get('profile')
  async getProfile(@Req() req: any) {
    const userEmail = req.user.email;
    const user = await this.userService.findByEmail(userEmail);
    if (!user) {
    // Optional: throw an exception if somehow the user is missing
    throw new NotFoundException('User not found');
  }
    return {
      email: user.email,
      roles: user.roles,
        
    };
  }
}
