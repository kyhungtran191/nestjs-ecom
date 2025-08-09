import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common'

import { AUTH_TYPE_KEY, AuthTypeDecoratorPayload } from '../decorators/auth.decorator'
import { Reflector } from '@nestjs/core'
import { AccessTokenGuard } from './access-token.guard'
import { APIKeyGuard } from './x-api-key.guard'
import { AuthType, ConditionGuard } from '../constants/auth.const'

@Injectable()
export class AuthenticationGuard implements CanActivate {
  private readonly authTypeGuardMap: Record<string, CanActivate> = {
    [AuthType.Bearer]: this.accessTokenGuard,
    [AuthType.APIKey]: this.apiKeyGuard,
    [AuthType.None]: { canActivate: () => false },
  }
  constructor(
    private reflector: Reflector,
    private readonly accessTokenGuard: AccessTokenGuard,
    private readonly apiKeyGuard: APIKeyGuard,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Get value from the decorator
    const authTypeValues = this.reflector.getAllAndOverride<AuthTypeDecoratorPayload | undefined>(AUTH_TYPE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]) ?? {
      authTypes: [AuthType.None],
      options: {
        condition: 'or',
      },
    }

    const guards = authTypeValues.authTypes.map((authType) => this.authTypeGuardMap[authType])
    let error = new UnauthorizedException()
    // Check option
    if (authTypeValues.options.condition === ConditionGuard.OR) {
      for (const guard of guards) {
        const canActivate = await Promise.resolve(guard.canActivate(context)).catch((err) => {
          error = error
          return false
        })

        if (canActivate) {
          return true
        }
      }
      throw error
    } else {
      for (const guard of guards) {
        const canActivate = await Promise.resolve(guard.canActivate(context)).catch((err) => {
          error = error
          return false
        })

        if (!canActivate) {
          throw error
        }
      }
      return true
    }
  }
}
