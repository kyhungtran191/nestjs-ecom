// de decorator co the nam trong params cua controller phai dung createParams decorator

import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { REQUEST_USER_KEY } from '../constants/auth.const'
import { AccessTokenPayload } from '../types/jwt.type'

export const activeUser = createParamDecorator((field: keyof AccessTokenPayload | undefined, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest()
  const user: AccessTokenPayload | undefined = request[REQUEST_USER_KEY]
  return field ? user?.[field] : user
})
