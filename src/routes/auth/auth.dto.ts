import { createZodDto } from 'nestjs-zod'
import { RegisterBodySchema, RegisterResSchema } from './auth.model'

// class is required for using DTO as a type
export class RegisterBodyDTO extends createZodDto(RegisterBodySchema) {}
export class RegisterResDTO extends createZodDto(RegisterResSchema) {}
