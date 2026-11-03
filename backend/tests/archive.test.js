import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { createWriteStream } from 'node:fs'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import yazl from 'yazl'
import { ArchiveValidationError, extractZip, inspectZip, validateZipEntry } from '@secureship/archive'

const limits = { maxArchiveSize: 1024 * 1024, maxExpandedSize: 4 * 1024 * 1024, maxFiles: 10, maxFileSize: 1024 * 1024, maxCompressionRatio: 100, ratioCheckThreshold: 1024 }

async function createZip(entries, compress = false) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'secureship-test-'))
  const filename = path.join(directory, 'test.zip')
  const zip = new yazl.ZipFile()
  for (const [name, contents] of entries) zip.addBuffer(Buffer.from(contents), name, { compress })
  await new Promise((resolve, reject) => {
    const output = createWriteStream(filename)
    output.on('error', reject)
    output.on('close', resolve)
    zip.outputStream.on('error', reject).pipe(output)
    zip.end()
  })
  return { filename, cleanup: () => fs.rm(directory, { recursive: true, force: true }) }
}

test('inspects a valid archive without extracting it', async () => {
  const archive = await createZip([['src/app.js', 'console.log("ok")'], ['package.json', '{}']])
  try {
    assert.deepEqual(await inspectZip(archive.filename, limits), { entryCount: 2, fileCount: 2, expandedSize: 19 })
  } finally { await archive.cleanup() }
})

test('extracts validated files only beneath the disposable destination', async () => {
  const archive = await createZip([['src/app.js', 'safe source']])
  const destination = await fs.mkdtemp(path.join(os.tmpdir(), 'secureship-output-'))
  try {
    await extractZip(archive.filename, destination, limits)
    assert.equal(await fs.readFile(path.join(destination, 'src', 'app.js'), 'utf8'), 'safe source')
  } finally { await archive.cleanup(); await fs.rm(destination, { recursive: true, force: true }) }
})

test('rejects traversal, links, encrypted entries, and unsupported compression', () => {
  const base = { fileName: 'safe/file.js', externalFileAttributes: 0, generalPurposeBitFlag: 0, compressionMethod: 0, uncompressedSize: 1, compressedSize: 1 }
  assert.throws(() => validateZipEntry({ ...base, fileName: '../outside.js' }, limits), ArchiveValidationError)
  assert.throws(() => validateZipEntry({ ...base, externalFileAttributes: 0xa000 << 16 }, limits), ArchiveValidationError)
  assert.throws(() => validateZipEntry({ ...base, generalPurposeBitFlag: 1 }, limits), ArchiveValidationError)
  assert.throws(() => validateZipEntry({ ...base, compressionMethod: 99 }, limits), ArchiveValidationError)
})

test('rejects a non-zip file', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'secureship-test-'))
  const filename = path.join(directory, 'wrong.zip')
  try {
    await fs.writeFile(filename, 'not a zip archive')
    await assert.rejects(inspectZip(filename, limits), ArchiveValidationError)
  } finally { await fs.rm(directory, { recursive: true, force: true }) }
})

test('rejects compression bombs and excessive total expanded size', async () => {
  const ratioArchive = await createZip([['repeated.txt', 'a'.repeat(64 * 1024)]], true)
  const expandedArchive = await createZip(Array.from({ length: 5 }, (_, index) => [`file-${index}.bin`, randomBytes(900 * 1024)]), true)
  try {
    await assert.rejects(inspectZip(ratioArchive.filename, limits), /compression ratio/)
    await assert.rejects(inspectZip(expandedArchive.filename, { ...limits, maxArchiveSize: 6 * 1024 * 1024 }), /expands beyond/)
  } finally { await ratioArchive.cleanup(); await expandedArchive.cleanup() }
})
