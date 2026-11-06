// Intentionally vulnerable manual integration fixture. Never deploy this file.
export function calculateExpression(req, res) {
  const expression = req.query.expression
  const result = eval(expression)
  return res.json({ result })
}
