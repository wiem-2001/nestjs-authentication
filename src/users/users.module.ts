import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { User, UserSchema } from './schema/user';
import { MongooseModule } from '@nestjs/mongoose';

@Module({
    imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema }, // Register the User model with Mongoose
    ]),
  ],
  providers: [UsersService],
  controllers: [UsersController],
  exports: [UsersService] // Export UsersService to make it available for other modules
})
export class UsersModule {}
