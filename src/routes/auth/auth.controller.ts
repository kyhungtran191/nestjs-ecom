import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common'
import { AuthService } from './auth.service'
import { RegisterBodyDTO, RegisterResDTO } from './auth.dto'
import { ZodSerializerDto } from 'nestjs-zod'

@Controller('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ZodSerializerDto(RegisterResDTO)
  async register(@Body() body: RegisterBodyDTO) {
    return await this.authService.register(body)
  }

  @Post('login')
  async login(@Body() body: any) {
    return this.authService.login(body)
  }

  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Body() body: any) {
    return this.authService.refreshToken(body.refreshToken)
  }

  @Post('logout')
  async logout(@Body() body: any) {
    return this.authService.logout(body.refreshToken)
  }
}
