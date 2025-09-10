import { Injectable } from '@nestjs/common'
import { OAuth2Client } from 'google-auth-library'
import { google } from 'googleapis'
import envConfig from 'src/shared/config'
import { GoogleAuthStateType } from './auth.model'
import { AuthRepository } from './auth.repo'
import { HashingService } from 'src/shared/services/hashing.service'
import { RolesService } from './roles.service'
import { v4 as uuidv4 } from 'uuid'
import { AuthService } from './auth.service'

@Injectable()
export class GoogleService {
  private oauth2Client: OAuth2Client
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  constructor(
    private readonly hashingService: HashingService,
    private readonly rolesService: RolesService,
    private readonly authRepo: AuthRepository,
    private readonly authService: AuthService,
  ) {
    this.oauth2Client = new google.auth.OAuth2(
      envConfig.GOOGLE_CLIENT_ID,
      envConfig.GOOGLE_CLIENT_SECRET,
      envConfig.GOOGLE_REDIRECT_URI,
    )
  }
  getAuthorizationURl({ userAgent, ip }: GoogleAuthStateType) {
    const scope = ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']

    // Transfer Object to string base64 secure put in the URL
    const stateString = Buffer.from(
      JSON.stringify({
        userAgent,
        ip,
      }),
    ).toString('base64')

    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: scope,
      include_granted_scopes: true,
      state: stateString,
    })
    return url
  }
  async googleCallback({ code, state }: { code: string; state: string }) {
    // 1. get state from URL
    try {
      let userAgent = 'Unknown'
      let ip = 'Unknown'
      try {
        if (state) {
          const clientInfo = JSON.parse(Buffer.from(state, 'base64').toString()) as GoogleAuthStateType
          userAgent = clientInfo.userAgent
          ip = clientInfo.ip
        }
      } catch (err) {
        console.log('Error parsing state')
      }
      // 2. Use code to get token
      const { tokens } = await this.oauth2Client.getToken(code)
      this.oauth2Client.setCredentials(tokens)
      //3. Get user info
      const oauth2 = google.oauth2({
        auth: this.oauth2Client,
        version: 'v2',
      })

      const { data } = await oauth2.userinfo.get()

      if (!data.email) {
        throw new Error('Cannot get user email from google')
      }

      let user = await this.authRepo.findUniqueIncludeRoleName({
        email: data.email,
      })

      //4. If new account -> register
      if (!user) {
        const clientRoleId = await this.rolesService.getClientRoleId()
        // Random password
        const randomPW = uuidv4()
        const hashedPW = await this.hashingService.hash(randomPW)
        user = await this.authRepo.createUserIncludeRole({
          email: data.email,
          name: data.name ?? '',
          password: hashedPW,
          roleId: clientRoleId,
          phoneNumber: '',
          avatar: data.picture ?? null,
        })
      }

      const device = await this.authRepo.createDevice({
        userId: user.id,
        ip,
        userAgent,
      })

      const authTokens = await this.authService.generateTokens({
        deviceId: device.id,
        roleId: user.role.id,
        roleName: user.role.name,
        userId: user.id,
      })

      return authTokens
      //
    } catch (err) {
      console.log(err)
      throw new Error('Đăng nhập bằng google that bai')
    }
  }
}
