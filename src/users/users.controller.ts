import { Auth } from './../../node_modules/mongodb/src/mongo_client';
import { Controller, Get, NotFoundException, Req, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';
import { Role } from 'src/common/enums/role';
import { Roles } from 'src/auth/decorators/role-decorator';
import { RolesGuard } from 'src/auth/guards/roles-guard';

@Controller('users')
export class UsersController {
    constructor(private readonly userService:UsersService) {}

  @UseGuards(AuthGuard('jwt'),RolesGuard)
  @Roles(Role.USER)
  @Get('profile')
  async getProfile(@Req() req: any) {
    const userEmail = req.user.email;
    const user = await this.userService.findByEmail(userEmail);
    if (!user) {
    throw new NotFoundException('User not found');
  }
    return {
      email: user.email,
      roles: user.roles,
        
    };
  }
}
