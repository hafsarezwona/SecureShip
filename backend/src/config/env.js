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
  N8N_SCAN_WEBHOOK_URL: optionalUrl,
  N8N_INTERNAL_SECRET: optionalString,
  WORKER_INTERNAL_URL: optionalUrl,
  WORKER_API_SECRET: optionalString,
  MAX_ARCHIVE_SIZE: z.coerce.number().int().positive().default(25 * 1024 * 1024),
  MAX_EXTRACTED_SIZE: z.coerce.number().int().positive().default(250 * 1024 * 1024),
  MAX_ARCHIVE_FILES: z.coerce.number().int().positive().default(5000),
  MAX_COMPRESSION_RATIO: z.coerce.number().positive().default(100),
  SCAN_TEMP_DIRECTORY: z.string().default(''),
})

export const env = schema.parse(process.env)
export const hasSupabase = Boolean(env.SUPABASE_URL && env.SUPABASE_ANON_KEY)
export const hasScanOrchestrator = Boolean(hasSupabase && env.SUPABASE_SERVICE_ROLE_KEY && env.SUPABASE_STORAGE_BUCKET && env.N8N_SCAN_WEBHOOK_URL && env.N8N_INTERNAL_SECRET && env.WORKER_INTERNAL_URL && env.WORKER_API_SECRET)
