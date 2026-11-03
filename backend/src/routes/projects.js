import { Router } from 'express'
import { z } from 'zod'
import { requireUser } from '../middleware/auth.js'

const router = Router()
const projectSchema = z.object({
  name: z.string().trim().min(1).max(80),
  description: z.string().trim().max(500).optional().default(''),
  primary_language: z.string().trim().max(40).optional().default(''),
  framework: z.string().trim().max(80).optional().default(''),
})

router.use(requireUser)

router.get('/', async (req, res, next) => {
  const { data, error } = await req.db.from('projects').select('id,name,description,primary_language,framework,created_at,updated_at').order('created_at', { ascending: false })
  if (error) return next(error)
  res.json({ projects: data })
})

router.post('/', async (req, res, next) => {
  const parsed = projectSchema.safeParse(req.body)
  if (!parsed.success) return res.status(400).json({ error: { message: 'Enter a project name and valid project details.' } })
  const { data, error } = await req.db.from('projects').insert({ ...parsed.data, user_id: req.user.id }).select('id,name,description,primary_language,framework,created_at,updated_at').single()
  if (error) return next(error)
  res.status(201).json({ project: data })
})

router.get('/:projectId', async (req, res, next) => {
  const { data, error } = await req.db.from('projects').select('id,name,description,primary_language,framework,created_at,updated_at').eq('id', req.params.projectId).maybeSingle()
  if (error) return next(error)
  if (!data) return res.status(404).json({ error: { message: 'Project not found.' } })
  const { data: scans, error: scansError } = await req.db.from('scans').select('id,status,started_at,completed_at,created_at').eq('project_id', data.id).order('created_at', { ascending: false }).limit(50)
  if (scansError) return next(scansError)
  res.json({ project: data, scans })
})

router.patch('/:projectId', async (req, res, next) => {
  const parsed = projectSchema.partial().safeParse(req.body)
  if (!parsed.success || !Object.keys(parsed.data || {}).length) return res.status(400).json({ error: { message: 'Provide valid project details to update.' } })
  const { data, error } = await req.db.from('projects').update(parsed.data).eq('id', req.params.projectId).select('id,name,description,primary_language,framework,created_at,updated_at').maybeSingle()
  if (error) return next(error)
  if (!data) return res.status(404).json({ error: { message: 'Project not found.' } })
  res.json({ project: data })
})

router.delete('/:projectId', async (req, res, next) => {
  const { data, error } = await req.db.from('projects').delete().eq('id', req.params.projectId).select('id').maybeSingle()
  if (error) return next(error)
  if (!data) return res.status(404).json({ error: { message: 'Project not found.' } })
  res.status(204).end()
})

export default router
