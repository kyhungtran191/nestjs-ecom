import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common'

import envConfig from '../config'

@Injectable()
export class APIKeyGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest()
    const xAPIKey = request.headers['x-api-key']
    if (xAPIKey !== envConfig.API_X_KEY) return false
    return true
  }
}
