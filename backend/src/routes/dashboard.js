import { Router } from 'express'
import { requireUser } from '../middleware/auth.js'

const router = Router()
router.use(requireUser)

router.get('/', async (req, res, next) => {
  const [projects, scans, openFindings, verifiedFindings] = await Promise.all([
    req.db.from('projects').select('id,name,primary_language,framework,created_at', { count: 'exact' }).order('created_at', { ascending: false }),
    req.db.from('scans').select('id,project_id,status,created_at,projects(name)', { count: 'exact' }).order('created_at', { ascending: false }).limit(5),
    req.db.from('findings').select('id', { count: 'exact', head: true }).in('status', ['detected', 'under_review', 'remediation_proposed', 'remediated', 'reopened']),
    req.db.from('findings').select('id', { count: 'exact', head: true }).eq('status', 'verified_resolved'),
  ])
  const failure = projects.error || scans.error || openFindings.error || verifiedFindings.error
  if (failure) return next(failure)
  res.json({
    projects: projects.data,
    totalScans: scans.count || 0,
    openFindings: openFindings.count || 0,
    verifiedFindings: verifiedFindings.count || 0,
    recentScans: scans.data.map(scan => ({ ...scan, project_name: scan.projects?.name || 'Project' })),
  })
})

export default router
