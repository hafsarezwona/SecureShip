import { Router } from 'express'
import { requireUser } from '../middleware/auth.js'
import { z } from 'zod'

const router = Router()
router.use(requireUser)

router.get('/', async (req, res, next) => {
  let query = req.db.from('findings').select('id,scanner,rule_id,title,severity,file_path,line_start,status,description,created_at').order('created_at', { ascending: false }).limit(100)
  if (req.query.severity) query = query.eq('severity', String(req.query.severity).toLowerCase())
  if (req.query.projectId) query = query.eq('project_id', String(req.query.projectId))
  const { data, error } = await query
  if (error) return next(error)
  res.json({ findings: data })
})

router.get('/:findingId', async (req, res, next) => {
  if (!z.string().uuid().safeParse(req.params.findingId).success) return res.status(404).json({ error: { message: 'Finding not found.' } })
  const { data, error } = await req.db.from('findings')
    .select('id,scan_id,project_id,scanner,rule_id,title,severity,cwe_id,owasp_category,file_path,line_start,line_end,description,evidence_redacted,ai_explanation,business_impact,remediation_guidance,status,created_at,updated_at')
    .eq('id', req.params.findingId)
    .maybeSingle()
  if (error) return next(error)
  if (!data) return res.status(404).json({ error: { message: 'Finding not found.' } })
  res.json({ finding: data })
})

export default router
