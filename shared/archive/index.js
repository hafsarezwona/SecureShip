import fs from 'node:fs/promises'
import { createWriteStream } from 'node:fs'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'
import yauzl from 'yauzl'

const WINDOWS_DEVICE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i

export class ArchiveValidationError extends Error {
  constructor(message) { super(message); this.name = 'ArchiveValidationError' }
}

export function validateZipEntry(entry, limits, seen = new Set()) {
  const name = entry.fileName
  const libraryError = yauzl.validateFileName(name)
  if (libraryError) throw new ArchiveValidationError('The ZIP contains an unsafe file path.')
  if (!name || name.includes('\\') || name.includes('\0') || name.startsWith('//') || /^[a-z]:/i.test(name) || name.startsWith('~')) {
    throw new ArchiveValidationError('The ZIP contains an unsafe file path.')
  }
  const parts = name.replace(/\/$/, '').split('/')
  if (name.length > 1024 || parts.length > 32 || parts.some(part => part.length > 240 || !part || part === '.' || part === '..' || /[:. ]$/.test(part) || WINDOWS_DEVICE.test(part))) {
    throw new ArchiveValidationError('The ZIP contains an unsupported file path.')
  }

  const normalized = name.normalize('NFC').replace(/\/$/, '').toLocaleLowerCase('en-US')
  if (seen.has(normalized)) throw new ArchiveValidationError('The ZIP contains duplicate file paths.')
  seen.add(normalized)

  const unixMode = (entry.externalFileAttributes >>> 16) & 0xffff
  const fileType = unixMode & 0xf000
  if (fileType === 0xa000) throw new ArchiveValidationError('Symbolic links are not accepted in uploaded ZIP files.')
  if (fileType && fileType !== 0x8000 && fileType !== 0x4000) throw new ArchiveValidationError('The ZIP contains an unsupported special file.')
  if (entry.generalPurposeBitFlag & 1) throw new ArchiveValidationError('Encrypted ZIP entries are not supported.')
  if (![0, 8].includes(entry.compressionMethod)) throw new ArchiveValidationError('The ZIP uses an unsupported compression method.')
  if (!Number.isSafeInteger(entry.uncompressedSize) || !Number.isSafeInteger(entry.compressedSize) || entry.uncompressedSize < 0 || entry.compressedSize < 0) {
    throw new ArchiveValidationError('The ZIP contains invalid entry sizes.')
  }

  if (entry.uncompressedSize > limits.maxFileSize) throw new ArchiveValidationError('A file in the ZIP exceeds the per-file expanded size limit.')
  const ratio = entry.compressedSize === 0 ? (entry.uncompressedSize === 0 ? 1 : Infinity) : entry.uncompressedSize / entry.compressedSize
  if (ratio > limits.maxCompressionRatio && entry.uncompressedSize > limits.ratioCheckThreshold) {
    throw new ArchiveValidationError('The ZIP contains a suspicious compression ratio.')
  }
  return { uncompressedSize: entry.uncompressedSize, isDirectory: name.endsWith('/') }
}

export async function extractZip(filePath, destination, limits) {
  await inspectZip(filePath, limits)
  const root = path.resolve(destination)
  await fs.mkdir(root, { recursive: true, mode: 0o700 })
  const zip = await yauzl.openPromise(filePath, { lazyEntries: true, strictFileNames: true, validateEntrySizes: true })
  const seen = new Set()
  try {
    for await (const entry of zip.eachEntry()) {
      const result = validateZipEntry(entry, limits, seen)
      const target = path.resolve(root, entry.fileName)
      if (!target.startsWith(`${root}${path.sep}`)) throw new ArchiveValidationError('The ZIP contains an unsafe file path.')
      if (result.isDirectory) {
        await fs.mkdir(target, { recursive: true, mode: 0o700 })
        continue
      }
      await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 })
      const stream = await new Promise((resolve, reject) => zip.openReadStream(entry, (error, readable) => error ? reject(error) : resolve(readable)))
      await pipeline(stream, createWriteStream(target, { flags: 'wx', mode: 0o600 }))
    }
  } catch (error) {
    if (error instanceof ArchiveValidationError) throw error
    throw new ArchiveValidationError('The ZIP could not be extracted safely.')
  } finally { if (zip.isOpen) zip.close() }
  return root
}

export async function inspectZip(filePath, limits) {
  const file = await fs.stat(filePath)
  if (file.size < 22 || file.size > limits.maxArchiveSize) throw new ArchiveValidationError('The ZIP size is outside the allowed range.')
  const signature = Buffer.alloc(4)
  const handle = await fs.open(filePath, 'r')
  try { await handle.read(signature, 0, 4, 0) } finally { await handle.close() }
  if (signature[0] !== 0x50 || signature[1] !== 0x4b) throw new ArchiveValidationError('The uploaded file is not a valid ZIP archive.')

  let zip
  try {
    zip = await yauzl.openPromise(filePath, { lazyEntries: true, strictFileNames: true, validateEntrySizes: true })
    let entryCount = 0
    let expandedSize = 0
    let fileCount = 0
    const seen = new Set()
    for await (const entry of zip.eachEntry()) {
      entryCount += 1
      if (entryCount > limits.maxFiles) throw new ArchiveValidationError('The ZIP contains too many entries.')
      const result = validateZipEntry(entry, limits, seen)
      const stream = await new Promise((resolve, reject) => zip.openReadStream(entry, (error, readable) => error ? reject(error) : resolve(readable)))
      let actualSize = 0
      for await (const chunk of stream) {
        actualSize += chunk.length
        if (actualSize > limits.maxFileSize || expandedSize + actualSize > limits.maxExpandedSize) {
          stream.destroy()
          throw new ArchiveValidationError('The ZIP expands beyond the allowed size.')
        }
      }
      if (actualSize !== result.uncompressedSize) throw new ArchiveValidationError('The ZIP contains inconsistent entry sizes.')
      expandedSize += actualSize
      if (expandedSize > limits.maxExpandedSize) throw new ArchiveValidationError('The ZIP expands beyond the allowed size.')
      if (!result.isDirectory) fileCount += 1
    }
    if (fileCount === 0) throw new ArchiveValidationError('The ZIP does not contain any files.')
    return { entryCount, fileCount, expandedSize }
  } catch (error) {
    if (error instanceof ArchiveValidationError) throw error
    throw new ArchiveValidationError('The ZIP is malformed or could not be inspected safely.')
  } finally { if (zip?.isOpen) zip.close() }
}

export function archiveLimits(env) {
  return {
    maxArchiveSize: env.MAX_ARCHIVE_SIZE,
    maxExpandedSize: env.MAX_EXTRACTED_SIZE,
    maxFiles: env.MAX_ARCHIVE_FILES,
    maxFileSize: Math.min(env.MAX_EXTRACTED_SIZE, 100 * 1024 * 1024),
    maxCompressionRatio: env.MAX_COMPRESSION_RATIO,
    ratioCheckThreshold: 1024 * 1024,
  }
}
