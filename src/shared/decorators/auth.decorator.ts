import { SetMetadata } from '@nestjs/common'
import { AuthType, AuthTypeType, ConditionGuard, ConditionGuardType } from '../constants/auth.const'

export const AUTH_TYPE_KEY = 'authType'
export type AuthTypeDecoratorPayload = {
  authTypes: AuthTypeType[]
  options: {
    condition: ConditionGuardType
  }
}
export const Auth = (authTypes: AuthTypeType[], options?: { condition?: ConditionGuardType } | undefined) => {
  //SetMetaData let us create a customer decorator
  return SetMetadata(AUTH_TYPE_KEY, { authTypes, options: options ?? { condition: ConditionGuard.AND } })
}

export const IsPublic = () => Auth([AuthType.None])
