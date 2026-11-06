export async function getFindingForUser({ db, findingId, userId }) {
  const { data, error } = await db.from('findings')
    .select('id,scan_id,project_id,user_id,scanner,rule_id,title,severity,cwe_id,owasp_category,file_path,line_start,line_end,description,fingerprint,ai_explanation')
    .eq('id', findingId)
    .eq('user_id', userId)
    .maybeSingle()
  if (error) throw error
  return data?.user_id === userId ? data : null
}

export async function persistFindingAnalysis({ admin, findingId, userId, scanId, analysis }) {
  const { data, error } = await admin.from('findings').update({
    ai_explanation: analysis,
    business_impact: analysis.business_impact,
    remediation_guidance: analysis.remediation_guidance,
  }).eq('id', findingId).eq('user_id', userId).eq('scan_id', scanId).select('id').maybeSingle()
  if (error) throw error
  return Boolean(data)
}
