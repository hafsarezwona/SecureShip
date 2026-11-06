import 'dotenv/config'
import { z } from 'zod'

const optionalString = z.preprocess(value => value === '' ? undefined : value, z.string().optional())
const optionalUrl = z.preprocess(value => value === '' ? undefined : value, z.string().url().optional())
const schema = z.object({
  PORT: z.coerce.number().int().positive().default(4000),
  WEB_ORIGIN: z.string().default('http://localhost:5173'),
  SUPABASE_URL: optionalUrl,
  SUPABASE_ANON_KEY: optionalString,
  SUPABASE_SERVICE_ROLE_KEY: optionalString,
  SUPABASE_STORAGE_BUCKET: z.string().default('secure-source'),
  AI_API_KEY: optionalString,
  OPENAI_MODEL: z.preprocess(value => typeof value === 'string' && value.trim() === '' ? undefined : value, z.string().trim().min(1).max(128).default('gpt-6-luna')),
  WORKER_INTERNAL_URL: optionalUrl,
  WORKER_API_SECRET: optionalString,
  MAX_ARCHIVE_SIZE: z.coerce.number().int().positive().default(25 * 1024 * 1024),
  MAX_EXTRACTED_SIZE: z.coerce.number().int().positive().default(250 * 1024 * 1024),
  MAX_ARCHIVE_FILES: z.coerce.number().int().positive().default(5000),
  MAX_COMPRESSION_RATIO: z.coerce.number().positive().default(100),
  SCAN_TEMP_DIRECTORY: z.string().default(''),
  SSLCOMMERZ_STORE_ID: optionalString,
  SSLCOMMERZ_STORE_PASSWORD: optionalString,
  SSLCOMMERZ_SANDBOX: z.preprocess(value => value === 'false' ? false : value === 'true' ? true : value, z.boolean().default(true)),
  BILLING_API_PUBLIC_URL: optionalUrl,
  PREMIUM_PRICE_BDT: z.coerce.number().min(10).default(1000),
})

export const env = schema.parse(process.env)
export const hasSupabase = Boolean(env.SUPABASE_URL && env.SUPABASE_ANON_KEY)
export const hasAI = Boolean(env.AI_API_KEY)
export const hasScanner = Boolean(hasSupabase && env.SUPABASE_SERVICE_ROLE_KEY && env.SUPABASE_STORAGE_BUCKET && env.WORKER_INTERNAL_URL && env.WORKER_API_SECRET)
