import { Injectable } from '@nestjs/common'
import { PrismaService } from '../services/prisma.service'
import { UserType } from '../models/share-user.model'

@Injectable()
export class ShareUserRepository {
  constructor(private readonly prismaService: PrismaService) {}
  //   Find unique user account -> return UserType | null
  async findUnique(uniqueObject: { email: string } | { id: number }): Promise<UserType | null> {
    return await this.prismaService.user.findUnique({
      where: uniqueObject,
    })
  }
  
}
