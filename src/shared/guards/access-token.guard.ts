import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common'

import { TokenService } from '../services/token.service'
import { REQUEST_USER_KEY } from '../constants/auth.const'

@Injectable()
export class AccessTokenGuard implements CanActivate {
  constructor(private readonly tokenService: TokenService) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()
    const token = request.headers?.authorizations?.split(' ')[1]
    if (!token) {
      return false
    }
    try {
      const decodeToken = await this.tokenService.verifyAccessToken(token)
      request[REQUEST_USER_KEY] = decodeToken
      return true
    } catch (err) {
      return false
    }
  }
}
