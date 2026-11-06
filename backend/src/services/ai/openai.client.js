import OpenAI from 'openai'
import { env } from '../../config/env.js'

export const openaiClient = env.AI_API_KEY
  ? new OpenAI({ apiKey: env.AI_API_KEY, timeout: 30_000, maxRetries: 1 })
  : null
