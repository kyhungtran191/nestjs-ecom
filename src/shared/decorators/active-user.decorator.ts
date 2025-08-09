// de decorator co the nam trong params cua controller phai dung createParams decorator

import { createParamDecorator, ExecutionContext } from '@nestjs/common'
import { TokenPayload } from '../types/jwt.type'
import { REQUEST_USER_KEY } from '../constants/auth.const'

export const activeUser = createParamDecorator((field: keyof TokenPayload | undefined, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest()
  const user: TokenPayload | undefined = request[REQUEST_USER_KEY]
  return field ? user?.[field] : user
})
