import { Router } from 'express'
import { requireUser } from '../middleware/auth.js'

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

export default router
