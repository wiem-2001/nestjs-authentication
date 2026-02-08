import { IsString } from 'class-validator';

export class VerifyResetLinkDto {
  @IsString()
  resetSessionToken: string;
}
