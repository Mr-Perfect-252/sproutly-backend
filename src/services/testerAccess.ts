import { createHash, randomBytes } from 'crypto'
import jwt from 'jsonwebtoken'
import { JWT_SECRET } from '../middleware/auth'

export function createOpaqueToken(): string {
  return randomBytes(32).toString('base64url')
}

export function hashOpaqueToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

export function createDevelopmentDownloadToken(releaseId: string, appId: string, accessTokenHash: string): string {
  return jwt.sign(
    { scope: 'development_download', releaseId, appId, accessTokenHash },
    JWT_SECRET,
    { expiresIn: '5m' },
  )
}

export function getDevelopmentDownloadAccessHash(token: string, releaseId: string, appId: string): string | null {
  try {
    const payload = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload
    if (payload.scope === 'development_download'
      && payload.releaseId === releaseId
      && payload.appId === appId
      && typeof payload.accessTokenHash === 'string') return payload.accessTokenHash
    return null
  } catch {
    return null
  }
}
