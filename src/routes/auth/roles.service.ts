import { Injectable } from '@nestjs/common'
import { PrismaService } from 'src/shared/services/prisma.service'
import { Role } from '@prisma/client'
import { RoleName } from 'src/shared/constants/role.const'

@Injectable()
export class RolesService {
  private clientRoleId: number | null = null

  constructor(private readonly prismaService: PrismaService) {}

  async getClientRoleId() {
    if (this.clientRoleId) {
      return this.clientRoleId
    }
    const role = await this.prismaService.role.findFirst({
      where: {
        name: RoleName.Client,
      },
    })
    if (!role) {
      throw new Error("Role 'Client' not found")
    }
    this.clientRoleId = role.id
    return role.id
  }
}
