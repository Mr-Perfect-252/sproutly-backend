import AdmZip from 'adm-zip'
import crypto from 'crypto'
import fs from 'fs'

export interface ApkMeta {
  packageName: string
  versionName: string
  versionCode: number
  minSdk: number
  targetSdk: number
  sha256: string
  certFingerprint: string
  certFingerprintLegacy: string
  sizeBytes: number
}

/** Compute SHA-256 of a file using streams to prevent OOM memory exhaustion */
function streamSha256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)
    stream.on('data', chunk => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
    stream.on('error', reject)
  })
}

function safeReadUInt8(buf: Buffer, offset: number): number {
  if (offset < 0 || offset >= buf.length) return 0
  return buf[offset]
}

function safeReadUInt16LE(buf: Buffer, offset: number): number {
  if (offset < 0 || offset + 2 > buf.length) return 0
  return buf.readUInt16LE(offset)
}

function safeReadUInt32LE(buf: Buffer, offset: number): number {
  if (offset < 0 || offset + 4 > buf.length) return 0
  return buf.readUInt32LE(offset)
}

function safeReadInt32LE(buf: Buffer, offset: number): number {
  if (offset < 0 || offset + 4 > buf.length) return 0
  return buf.readInt32LE(offset)
}

/**
 * Decode binary Android XML (AXML) Manifest
 */
function parseManifestBuffer(buf: Buffer): {
  packageName: string
  versionName: string
  versionCode: number
  minSdk: number
  targetSdk: number
} {
  let packageName = ''
  let versionName = '1.0.0'
  let versionCode = 1
  let minSdk = 21
  let targetSdk = 34

  if (!buf || buf.length < 8) {
    return { packageName, versionName, versionCode, minSdk, targetSdk }
  }

  try {
    const strings: string[] = []
    let pos = 0

    // Magic number check: 0x00080003
    const magic = safeReadUInt32LE(buf, 0)
    if (magic !== 0x00080003) {
      // Not standard AXML, fallback to string search
      return extractStringsFromBufferFallback(buf)
    }

    pos = 8 // skip AXML header (4 bytes magic + 4 bytes file size)

    // Parse chunks
    while (pos < buf.length - 8) {
      const chunkType = safeReadUInt16LE(buf, pos)
      const headerSize = safeReadUInt16LE(buf, pos + 2)
      const chunkSize = safeReadUInt32LE(buf, pos + 4)

      if (chunkSize <= 0 || pos + chunkSize > buf.length + 8) {
        break
      }

      // RES_STRING_POOL_TYPE = 0x0001
      if (chunkType === 0x0001) {
        const stringCount = safeReadUInt32LE(buf, pos + 8)
        const flags = safeReadUInt32LE(buf, pos + 16)
        const stringsStart = safeReadUInt32LE(buf, pos + 20)
        const isUtf8 = (flags & (1 << 8)) !== 0

        const offsetsBase = pos + (headerSize > 0 ? headerSize : 28)
        const strDataBase = pos + stringsStart

        for (let i = 0; i < stringCount; i++) {
          const strOffset = safeReadUInt32LE(buf, offsetsBase + i * 4)
          const target = strDataBase + strOffset

          if (target >= buf.length) {
            strings.push('')
            continue
          }

          try {
            if (isUtf8) {
              // In UTF-8: first length is char count, second length is byte count
              let lenOffset = target
              let u8Len = safeReadUInt8(buf, lenOffset)
              if (u8Len & 0x80) lenOffset += 2
              else lenOffset += 1

              let byteLen = safeReadUInt8(buf, lenOffset)
              if (byteLen & 0x80) {
                byteLen = ((byteLen & 0x7f) << 8) | safeReadUInt8(buf, lenOffset + 1)
                lenOffset += 2
              } else {
                lenOffset += 1
              }

              const end = Math.min(buf.length, lenOffset + byteLen)
              const str = buf.toString('utf8', lenOffset, end)
              strings.push(str)
            } else {
              // UTF-16LE
              let charLen = safeReadUInt16LE(buf, target)
              let lenOffset = target + 2
              if (charLen & 0x8000) {
                const charLen2 = safeReadUInt16LE(buf, target + 2)
                charLen = ((charLen & 0x7fff) << 16) | charLen2
                lenOffset = target + 4
              }
              const end = Math.min(buf.length, lenOffset + charLen * 2)
              const str = buf.toString('utf16le', lenOffset, end)
              strings.push(str)
            }
          } catch {
            strings.push('')
          }
        }
      }

      // RES_XML_START_ELEMENT_TYPE = 0x0102
      if (chunkType === 0x0102) {
        const attrCount = safeReadUInt16LE(buf, pos + 20)
        const attrStart = pos + (headerSize > 0 ? headerSize : 28)
        const ATTR_SIZE = 20

        const pkgIdx = strings.indexOf('package')
        const vnIdx = strings.indexOf('versionName')
        const vcIdx = strings.indexOf('versionCode')
        const minIdx = strings.indexOf('minSdkVersion')
        const tgtIdx = strings.indexOf('targetSdkVersion')

        for (let a = 0; a < attrCount; a++) {
          const aOff = attrStart + a * ATTR_SIZE
          if (aOff + ATTR_SIZE > buf.length) break

          const nameIdx = safeReadInt32LE(buf, aOff + 4)
          const valueType = safeReadUInt8(buf, aOff + 15)
          const rawValue = safeReadInt32LE(buf, aOff + 16)

          if (nameIdx >= 0 && nameIdx < strings.length) {
            const attrName = strings[nameIdx]
            if (attrName === 'package' || nameIdx === pkgIdx) {
              if (valueType === 0x03 && rawValue >= 0 && rawValue < strings.length) {
                packageName = strings[rawValue] || packageName
              }
            } else if (attrName === 'versionName' || nameIdx === vnIdx) {
              if (valueType === 0x03 && rawValue >= 0 && rawValue < strings.length) {
                versionName = strings[rawValue] || versionName
              }
            } else if (attrName === 'versionCode' || nameIdx === vcIdx) {
              if (rawValue > 0) versionCode = rawValue
            } else if (attrName === 'minSdkVersion' || nameIdx === minIdx) {
              if (rawValue > 0) minSdk = rawValue
            } else if (attrName === 'targetSdkVersion' || nameIdx === tgtIdx) {
              if (rawValue > 0) targetSdk = rawValue
            }
          }
        }
      }

      pos += chunkSize
    }
  } catch {
    // Fallback if parsing encountered any issue
    return extractStringsFromBufferFallback(buf)
  }

  if (!packageName) {
    const fallback = extractStringsFromBufferFallback(buf)
    packageName = fallback.packageName || packageName
    if (fallback.versionName && fallback.versionName !== '1.0.0') versionName = fallback.versionName
    if (fallback.versionCode && fallback.versionCode !== 1) versionCode = fallback.versionCode
  }

  return { packageName, versionName, versionCode, minSdk, targetSdk }
}

/**
 * Fallback pattern extraction if binary chunk structure is obfuscated or non-standard
 */
function extractStringsFromBufferFallback(buf: Buffer): {
  packageName: string
  versionName: string
  versionCode: number
  minSdk: number
  targetSdk: number
} {
  const utf8 = buf.toString('utf8')
  const utf16 = buf.toString('utf16le')
  const combined = utf8 + '\n' + utf16

  // Find package name: e.g. com.example.app
  let packageName = ''
  const pkgMatch = combined.match(/([a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z][a-zA-Z0-9_]+(?:\.[a-zA-Z][a-zA-Z0-9_]+)+)/)
  if (pkgMatch) {
    packageName = pkgMatch[1]
  }

  let versionName = '1.0.0'
  const vnMatch = combined.match(/\bv?(\d+\.\d+(?:\.\d+)?)\b/)
  if (vnMatch) {
    versionName = vnMatch[1]
  }

  return {
    packageName,
    versionName,
    versionCode: 1,
    minSdk: 21,
    targetSdk: 34,
  }
}

/**
 * Read a single DER TLV element at `off` and return its content bounds.
 */
function readTlv(buf: Buffer, off: number): { contentStart: number; totalEnd: number } {
  let p = off + 1
  let len = buf[p++]
  if (len & 0x80) {
    const n = len & 0x7f
    len = 0
    for (let i = 0; i < n; i++) len = (len << 8) | buf[p++]
  }
  return { contentStart: p, totalEnd: p + len }
}

/**
 * Pull the first X.509 certificate DER out of a PKCS#7/CMS SignedData blob
 * (the contents of META-INF/CERT.RSA). Returns null if the structure is unfamiliar.
 */
function firstCertificateDer(buf: Buffer): Buffer | null {
  try {
    const outer = readTlv(buf, 0)                  // SEQUENCE
    let off = outer.contentStart
    off = readTlv(buf, off).totalEnd               // OID (pkcs7-signedData)
    const ctx0 = readTlv(buf, off)                 // [0] explicit
    const signedData = readTlv(buf, ctx0.contentStart)
    let p = signedData.contentStart
    p = readTlv(buf, p).totalEnd                   // version INTEGER
    p = readTlv(buf, p).totalEnd                   // digestAlgorithms SET
    p = readTlv(buf, p).totalEnd                   // encapContentInfo SEQUENCE
    const certificates = readTlv(buf, p)           // [0] certificates
    const cert = readTlv(buf, certificates.contentStart)
    return buf.subarray(certificates.contentStart, cert.totalEnd)
  } catch {
    return null
  }
}

const colonHex = (buf: Buffer): string =>
  crypto.createHash('sha256').update(buf).digest('hex').match(/.{2}/g)!.join(':').toUpperCase()

function findSignatureEntry(zip: AdmZip) {
  return zip.getEntries().find(e => /^META-INF\/.+\.(RSA|DSA|EC)$/i.test(e.entryName))
}

/**
 * The signing-certificate fingerprint: SHA-256 of the signer's X.509 certificate.
 * This is the value `apksigner`/`keytool` print, and it is STABLE across rebuilds
 * signed with the same key.
 *
 * NOTE: the previous implementation hashed the whole META-INF/CERT.RSA blob, which
 * embeds a per-build signature (it covers the APK contents), so it changed on every
 * single build even with an identical key — causing spurious "fingerprint mismatch"
 * rejections on the second upload.
 */
function extractCertFingerprint(zip: AdmZip): string {
  try {
    const sigEntry = findSignatureEntry(zip)
    if (!sigEntry) return ''
    const raw = sigEntry.getData()
    const certDer = firstCertificateDer(raw)
    return colonHex(certDer ?? raw)
  } catch {
    return ''
  }
}

/** Legacy fingerprint (SHA-256 of the whole CERT.RSA blob) — kept only for backward compatibility. */
function extractLegacyCertFingerprint(zip: AdmZip): string {
  try {
    const sigEntry = findSignatureEntry(zip)
    if (!sigEntry) return ''
    return colonHex(sigEntry.getData())
  } catch {
    return ''
  }
}

/** Certificate fingerprint of an in-memory APK buffer (used to re-verify existing releases). */
export function certFingerprintFromApkBuffer(buf: Buffer): string {
  try {
    const v1 = extractCertFingerprint(new AdmZip(buf))
    if (v1) return v1
  } catch {
    /* fall through to the APK Signing Block */
  }
  return certFingerprintFromV2Block(buf)
}

// ── APK Signature Scheme v2/v3 (APK Signing Block) ──────────────────────────
// Modern APKs (minSdk >= 24) are signed v2/v3 only and have no META-INF/*.RSA,
// so the JAR-signature path above finds nothing. Read the certificate straight
// from the signing block instead — this is what makes certificate pinning
// actually work for such apps.

function readU64LE(buf: Buffer, off: number): number {
  return Number(buf.readBigUInt64LE(off))
}

function readLp(buf: Buffer, off: number): { start: number; end: number; next: number } | null {
  if (off + 4 > buf.length) return null
  const len = buf.readUInt32LE(off)
  const start = off + 4
  const end = start + len
  if (len < 0 || end > buf.length) return null
  return { start, end, next: end }
}

function certFromSignerBlock(sb: Buffer): Buffer | null {
  try {
    const signers = readLp(sb, 0); if (!signers) return null            // sequence of signers
    const signer = readLp(sb, signers.start); if (!signer) return null  // first signer
    const signedData = readLp(sb, signer.start); if (!signedData) return null
    const digests = readLp(sb, signedData.start); if (!digests) return null
    const certs = readLp(sb, digests.next); if (!certs) return null
    const cert = readLp(sb, certs.start); if (!cert) return null        // first certificate
    return sb.subarray(cert.start, cert.end)
  } catch {
    return null
  }
}

function certFingerprintFromV2Block(apkBuf: Buffer): string {
  try {
    const magicOff = apkBuf.lastIndexOf(Buffer.from('APK Sig Block 42'))
    if (magicOff < 8) return ''
    const blkSize = readU64LE(apkBuf, magicOff - 8)
    const pairsStart = magicOff + 16 - blkSize
    const pairsEnd = magicOff - 8
    if (pairsStart < 0 || pairsEnd > apkBuf.length || pairsStart >= pairsEnd) return ''
    let p = pairsStart
    while (p + 8 <= pairsEnd) {
      const pairLen = readU64LE(apkBuf, p)
      if (pairLen < 4 || p + 8 + pairLen > apkBuf.length) break
      const id = apkBuf.readUInt32LE(p + 8)
      if (id === 0x7109871a || id === 0xf05368c0) {   // v2 | v3
        const cert = certFromSignerBlock(apkBuf.subarray(p + 12, p + 8 + pairLen))
        if (cert) return colonHex(cert)
      }
      p = p + 8 + pairLen
    }
    return ''
  } catch {
    return ''
  }
}

/** Certificate fingerprint from the APK Signing Block (v2/v3) using only the file tail. */
function certFingerprintFromApkFileTail(filePath: string): string {
  try {
    const size = fs.statSync(filePath).size
    const tailLen = Math.min(size, 4 * 1024 * 1024)
    const fd = fs.openSync(filePath, 'r')
    try {
      const buf = Buffer.alloc(tailLen)
      fs.readSync(fd, buf, 0, tailLen, size - tailLen)
      return certFingerprintFromV2Block(buf)
    } finally {
      fs.closeSync(fd)
    }
  } catch {
    return ''
  }
}

export async function parseApk(filePath: string): Promise<ApkMeta> {
  const sizeBytes = fs.statSync(filePath).size
  const sha256 = await streamSha256(filePath)

  let packageName = ''
  let versionName = '1.0.0'
  let versionCode = 1
  let minSdk = 21
  let targetSdk = 34
  let certFingerprint = ''
  let certFingerprintLegacy = ''

  try {
    const zip = new AdmZip(filePath)
    const manifestEntry = zip.getEntry('AndroidManifest.xml')
    if (manifestEntry) {
      const manifestBuf = manifestEntry.getData()
      const meta = parseManifestBuffer(manifestBuf)
      packageName = meta.packageName
      versionName = meta.versionName
      versionCode = meta.versionCode
      minSdk = meta.minSdk
      targetSdk = meta.targetSdk
    }
    certFingerprint = extractCertFingerprint(zip) || certFingerprintFromApkFileTail(filePath)
    certFingerprintLegacy = extractLegacyCertFingerprint(zip)
  } catch (err) {
    console.warn('[ApkParser] Warning parsing APK internal manifest:', err)
  }

  // Fallback: derive package name from filename if extraction was empty
  if (!packageName) {
    const base = filePath.replace(/\\/g, '/').split('/').pop() || 'unknown'
    packageName = base.replace(/\.apk$/i, '').replace(/[^a-zA-Z0-9.]/g, '.')
  }

  return {
    packageName,
    versionName,
    versionCode,
    minSdk,
    targetSdk,
    sha256,
    certFingerprint,
    certFingerprintLegacy,
    sizeBytes,
  }
}
