import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import {
  DeviceType,
  RefreshTokenType,
  RegisterBodyType,
  RegisterResType,
  RoleType,
  VerificationCodeType,
} from './auth.model'
import { UserType } from 'src/shared/models/share-user.model'
import { Device, VerificationCode } from '@prisma/client'
import { addMilliseconds } from 'date-fns'
import ms from 'ms'
import envConfig from 'src/shared/config'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.const'

@Injectable()
export class AuthRepository {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(
    user: Omit<RegisterBodyType, 'confirmPassword' | 'code'> & Pick<UserType, 'roleId'>,
  ): Promise<Omit<UserType, 'password' | 'totpSecret'>> {
    return this.prismaService.user.create({
      data: user,
      omit: {
        password: true,
        totpSecret: true,
      },
    })
  }

  async createVerificationCode(payload: Pick<VerificationCode, 'email' | 'type' | 'code' | 'expiresAt'>) {
    return this.prismaService.verificationCode.upsert({
      where: {
        email: payload.email,
      },
      create: payload,
      update: {
        ...payload,
        code: payload.code,
        expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_EXPIRES_IN)),
      },
    })
  }

  async findUniqueVerificationCode(
    uniqueValue:
      | { email: string }
      | { id: number }
      | {
          email: string
          code: string
          type: TypeOfVerificationCode
        },
  ): Promise<VerificationCodeType | null> {
    return this.prismaService.verificationCode.findUnique({
      where: uniqueValue,
    })
  }

  createRefreshToken(data: { token: string; userId: number; expiresAt: Date; deviceId: number }) {
    return this.prismaService.refreshToken.create({
      data,
    })
  }

  createDevice(
    data: Pick<DeviceType, 'userId' | 'userAgent' | 'ip'> & Partial<Pick<DeviceType, 'lastActive' | 'isActive'>>,
  ) {
    return this.prismaService.device.create({
      data,
    })
  }

  async findUniqueIncludeRoleName(
    uniqueObject: { email: string } | { id: number },
  ): Promise<(UserType & { role: RoleType }) | null> {
    return this.prismaService.user.findUnique({
      where: uniqueObject,
      include: {
        role: true,
      },
    })
  }

  async findUniqueRefreshTokenIncludeUserRole(uniqueObject: {
    token: string
  }): Promise<(RefreshTokenType & { user: UserType & { role: RoleType } }) | null> {
    return this.prismaService.refreshToken.findUnique({
      where: uniqueObject,
      include: {
        user: {
          include: {
            role: true,
          },
        },
      },
    })
  }

  updateDevice(deviceId: number, data: Partial<DeviceType>) {
    return this.prismaService.device.update({
      where: {
        id: deviceId,
      },
      data,
    })
  }

  deleteRefreshToken(uniqueObject: { token: string }): Promise<RefreshTokenType> {
    return this.prismaService.refreshToken.delete({
      where: uniqueObject,
    })
  }
}
