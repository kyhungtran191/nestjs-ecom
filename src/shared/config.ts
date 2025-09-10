//Check exist env or not
import fs from 'fs'
import path from 'path'
import z from 'zod'
import dotenv from 'dotenv'

// Life cycle Nestjs
dotenv.config()
// Check exist file env or not
if (!fs.existsSync(path.resolve('.env'))) {
  console.log('Not found find .env')
  process.exit(1)
}

// CHANGE IN HERE

const configSchema = z.object({
  DATABASE_URL: z.string(),
  ACCESS_TOKEN_SECRET: z.string(),
  ACCESS_TOKEN_EXPIRES_IN: z.string(),
  REFRESH_TOKEN_SECRET: z.string(),
  REFRESH_TOKEN_EXPIRES_IN: z.string(),
  API_X_KEY: z.string(),
  ADMIN_NAME: z.string(),
  ADMIN_PASSWORD: z.string(),
  ADMIN_EMAIL: z.string(),
  ADMIN_PHONE_NUMBER: z.string(),
  OTP_EXPIRES_IN: z.string(),
  RESEND_API_KEY: z.string(),
  GOOGLE_CLIENT_ID: z.string(),
  GOOGLE_CLIENT_SECRET: z.string(),
  GOOGLE_REDIRECT_URI: z.string(),
  GOOGLE_REDIRECT_CLIENT_URI: z.string(),
})

const configServer = configSchema.safeParse(process.env)

//convert Object to class
// const configServer = plainToInstance(ConfigSchema, process.env)
//Validate all fields
// const e = validateSync(configServer)

if (!configServer.success) {
  console.log('Các giá trị khai báo trong file .env không hợp lệ!')
  console.error(configServer.error)
  process.exit()
}

const envConfig = configServer.data

export default envConfig
