import { HttpException, Injectable, UnauthorizedException, UnprocessableEntityException } from '@nestjs/common'
import { RolesService } from 'src/routes/auth/roles.service'
import { generateOTP, isNotFoundPrismaError, isUniqueConstraintPrismaError } from 'src/shared/helper'
import { HashingService } from 'src/shared/services/hashing.service'
import { PrismaService } from 'src/shared/services/prisma.service'
import { TokenService } from 'src/shared/services/token.service'
import {
  ForgotPasswordBodyType,
  LoginBodyType,
  RefreshTokenBodyType,
  RegisterBodyType,
  SendOTPBodyType,
} from './auth.model'
import { AuthRepository } from './auth.repo'
import { ShareUserRepository } from 'src/shared/repositories/share-user.repo'
import { addMilliseconds } from 'date-fns'
import ms from 'ms'
import envConfig from 'src/shared/config'
import { EmailService } from 'src/shared/services/email.service'
import { AccessTokenPayloadCreate } from 'src/shared/types/jwt.type'
import {
  EmailAlreadyExistsException,
  EmailNotFoundException,
  InvalidOTPException,
  OTPExpiredException,
} from './error.model'
import { TypeOfVerificationCode } from 'src/shared/constants/auth.const'

@Injectable()
export class AuthService {
  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepo: AuthRepository,
    private readonly tokenService: TokenService,
    private readonly shareUserRepository: ShareUserRepository,
    private readonly emailService: EmailService,
  ) {}

  async validateVerificationCode({ email, code, type }: { email: string; code: string; type: TypeOfVerificationCode }) {
    const verificationCode = await this.authRepo.findUniqueVerificationCode({
      email,
      code,
      type,
    })

    if (!verificationCode) {
      throw InvalidOTPException
    }
    if (verificationCode.expiresAt < new Date()) {
      throw OTPExpiredException
    }
    return verificationCode
  }

  async register(body: RegisterBodyType) {
    try {
      // check if verification code is in db
      await this.validateVerificationCode({
        code: body.code,
        email: body.email,
        type: TypeOfVerificationCode.REGISTER,
      })

      const clientRoleId = await this.rolesService.getClientRoleId()
      const hashedPassword = await this.hashingService.hash(body.password)
      const user = this.authRepo.createUser({
        email: body.email,
        name: body.name,
        phoneNumber: body.phoneNumber,
        password: hashedPassword,
        roleId: clientRoleId,
      })

      await this.authRepo.deleteVerificationCode({
        code: body.code,
        email: body.email,
        type: TypeOfVerificationCode.REGISTER,
      })

      return user
    } catch (error) {
      if (isUniqueConstraintPrismaError(error)) {
        throw new UnprocessableEntityException([
          {
            message: 'Email existed',
            path: 'email',
          },
        ])
      }
      throw error
    }
  }

  async sendOTP(body: SendOTPBodyType) {
    const user = await this.shareUserRepository.findUnique({ email: body.email })
    if (body.type === TypeOfVerificationCode.REGISTER && user) {
      throw EmailAlreadyExistsException
    }
    if (body.type === TypeOfVerificationCode.FORGOT_PASSWORD && !user) {
      throw EmailNotFoundException
    }
    const code = generateOTP()

    const verificationCode = await this.authRepo.createVerificationCode({
      code,
      email: body.email,
      expiresAt: addMilliseconds(new Date(), ms(envConfig.OTP_EXPIRES_IN)),
      type: body.type,
    })

    const { error } = await this.emailService.sendOTP({ email: body.email, code: verificationCode.code })

    if (error) {
      throw new UnprocessableEntityException([
        {
          message: 'OTP that bai',
          path: 'code',
        },
      ])
    }
    return {
      message: 'Sent OTP successfully!',
    }
  }

  async login(body: LoginBodyType & { userAgent: string; ip: string }) {
    const user = await this.authRepo.findUniqueIncludeRoleName({
      email: body.email,
    })

    if (!user) {
      throw new UnprocessableEntityException([
        {
          message: 'Email is not exist',
          path: 'email',
        },
      ])
    }

    const isPasswordMatch = await this.hashingService.compare(body.password, user.password)
    if (!isPasswordMatch) {
      throw new UnprocessableEntityException([
        {
          field: 'password',
          error: 'Password is incorrect',
        },
      ])
    }

    const device = await this.authRepo.createDevice({
      userId: user.id,
      ip: body.ip,
      userAgent: body.userAgent,
    })

    const tokens = await this.generateTokens({
      deviceId: device.id,
      roleId: user.role.id,
      roleName: user.role.name,
      userId: user.id,
    })

    return tokens
  }

  async generateTokens(payload: AccessTokenPayloadCreate) {
    const [accessToken, refreshToken] = await Promise.all([
      this.tokenService.signAccessToken({
        userId: payload.userId,
        deviceId: payload.deviceId,
        roleId: payload.roleId,
        roleName: payload.roleName,
      }),
      this.tokenService.signRefreshToken(payload),
    ])
    const decodedRefreshToken = await this.tokenService.verifyRefreshToken(refreshToken)
    await this.authRepo.createRefreshToken({
      deviceId: payload.deviceId,
      expiresAt: new Date(decodedRefreshToken.exp * 1000),
      token: refreshToken,
      userId: payload.userId,
    })
    return { accessToken, refreshToken }
  }

  async refreshToken({
    refreshToken,
    ip,
    userAgent,
  }: RefreshTokenBodyType & {
    userAgent: string
    ip: string
  }) {
    try {
      // 1. check the userId is valid or not
      const { userId } = await this.tokenService.verifyRefreshToken(refreshToken)
      // 2. is refresh token existing on the db
      const refreshTokenInDB = await this.authRepo.findUniqueRefreshTokenIncludeUserRole({
        token: refreshToken,
      })
      if (!refreshTokenInDB) {
        throw new UnauthorizedException('Refresh token has been revoked')
      }

      const {
        deviceId,
        user: {
          roleId,
          role: { name: roleName },
        },
      } = refreshTokenInDB
      //3. Update device
      const $updateDevice = this.authRepo.updateDevice(deviceId, {
        ip,
        userAgent,
      })
      // 4. delete old token
      const $deleteRefreshToken = this.authRepo.deleteRefreshToken({
        token: refreshToken,
      })
      // 4. Tạo mới accessToken và refreshToken
      const $generateTokens = this.generateTokens({ userId, roleId, roleName, deviceId })

      const [, , tokens] = await Promise.all([$updateDevice, $deleteRefreshToken, $generateTokens])
      return tokens
    } catch (error) {
      if (error instanceof HttpException) {
        throw error
      }
      throw new UnauthorizedException()
    }
  }

  async logout(refreshToken: string) {
    try {
      // 1. check valid token
      await this.tokenService.verifyRefreshToken(refreshToken)
      // 2. delete token in database
      const deletedRefreshToken = await this.authRepo.deleteRefreshToken({
        token: refreshToken,
      })
      // 3. Update device
      await this.authRepo.updateDevice(deletedRefreshToken.deviceId, {
        isActive: false,
      })
      return { message: 'Logout successfully' }
    } catch (error) {
      // refresh token is refreshed
      // refresh is token
      if (isNotFoundPrismaError(error)) {
        throw new UnauthorizedException('Refresh token has been revoked')
      }

      throw new UnauthorizedException()
    }
  }

  async forgotPassword(body: ForgotPasswordBodyType) {
    const { code, newPassword, email } = body
    // 1. check if exist email
    const user = await this.shareUserRepository.findUnique({
      email,
    })
    if (!user) {
      throw EmailNotFoundException
    }
    // 2. check OTP
    await this.validateVerificationCode({
      code: body.code,
      email: body.email,
      type: TypeOfVerificationCode.FORGOT_PASSWORD,
    })
    // 3. Update new Password
    const hashPW = await this.hashingService.hash(body.newPassword)
    await this.authRepo.updateUser({ id: user.id }, { password: hashPW })
    // 4. Delete OTP code
    await this.authRepo.deleteVerificationCode({
      email: body.email,
      code: body.code,
      type: TypeOfVerificationCode.REGISTER,
    })
    return { message: 'Change password successfully' }
  }
}
