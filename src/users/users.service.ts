    import { Injectable } from '@nestjs/common';
    import { Model } from 'mongoose';
    import { User } from './schema/user/user';
    import { InjectModel } from '@nestjs/mongoose';
import { CreateUserDto } from './dtos/create-user-dto/create-user-dto';

    @Injectable()
    export class UsersService {
        constructor(
        @InjectModel(User.name) // this decorator injects the User model into the service 
        private readonly userModel: Model<User>,
    ) {}
    
    async findByEmail(email: string, withPassword = false) {
    const query = this.userModel.findOne({ email });
    if (withPassword) query.select('+password');
    return query.exec();
  }


  async create(userData:CreateUserDto) {
    return this.userModel.create(userData);
  }

  async updateRefreshToken(userId: string, refreshToken: string) {
    return this.userModel.findByIdAndUpdate(userId, { refreshToken }, { new: true });
  }

  async findOneByTokenAndExpirationDate(resetPasswordToken: string) {
    return this.userModel.findOne({
      resetPasswordToken,
      resetPasswordExpires: { $gt: new Date() },
    });
  }

}
