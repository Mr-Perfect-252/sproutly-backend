import { createHmac, timingSafeEqual } from 'crypto'
import jwt from 'jsonwebtoken'

export function verifyGitHubWebhookSignature(
  rawBody: Buffer,
  signature: string | undefined,
  secret: string,
): boolean {
  if (!signature || !/^sha256=[a-f0-9]{64}$/.test(signature)) return false
  const expected = Buffer.from(`sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`)
  const received = Buffer.from(signature)
  return expected.length === received.length && timingSafeEqual(expected, received)
}

export function createGitHubAppJwt(appId: string, privateKey: string): string {
  const now = Math.floor(Date.now() / 1000)
  return jwt.sign({ iat: now - 60 }, privateKey.replace(/\\n/g, '\n'), {
    algorithm: 'RS256',
    issuer: appId,
    expiresIn: 9 * 60,
  })
}
