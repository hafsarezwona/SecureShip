import assert from 'node:assert/strict'
import test from 'node:test'
import { apiErrorHandler } from '../src/middleware/error-handler.js'

test('database schema errors return a clear setup action without exposing database details', () => {
  const res = { statusCode: 200, status(code) { this.statusCode = code; return this }, json(body) { this.body = body; return this } }
  apiErrorHandler({ code: 'PGRST205', message: 'Could not find public.projects; internal details omitted.' }, {}, res, () => {})
  assert.equal(res.statusCode, 503)
  assert.match(res.body.error.message, /202611040001_initial_schema\.sql/)
  assert.doesNotMatch(res.body.error.message, /internal details/)
})

test('other backend errors remain generic', () => {
  const res = { statusCode: 200, status(code) { this.statusCode = code; return this }, json(body) { this.body = body; return this } }
  apiErrorHandler(new Error('sensitive internal failure'), {}, res, () => {})
  assert.equal(res.statusCode, 500)
  assert.equal(res.body.error.message, 'The request could not be completed.')
})
